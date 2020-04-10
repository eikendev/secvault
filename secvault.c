/**
 * @file
 * @author eikendev
 * @date 2018-01-16
 * @brief This module contains the kernel module.
 * @details The kernel module handles the vaults stored in kernel memory space.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/version.h>

#include <asm/uaccess.h>

#include "common.h"

/**
 * @brief Major device number for the created devices.
 */
#define MAJOR_NUM 231

/**
 * @brief Name of the module.
 */
#define MODNAME "secvault"

/**
 * @brief Struct used to store meta information of a vault.
 */
typedef struct {
	char key[KEYSIZE]; ///< The key used to encrypt the vault.
	char *data; ///< The data stored in the vault.
	struct cdev *driver; ///< The driver associated with the vault.
	struct semaphore sem; ///< The semaphore associated with the vault.
	unsigned long size; ///< The maximum size of the vault.
	unsigned long used_space; ///< The currently used size of the vault.
	dev_t number; ///< The device number of the driver associated with the vault.
	uid_t owner; ///< The owner that created the vault.
	int in_use; ///< Specifies whether the vault is currently in use.
} vault_t;

static dev_t dev_numbers;
static struct class *driver_class;

static dev_t ioctl_number;
static struct cdev *ioctl_driver;
static struct device *ioctl_dev;

static vault_t vaults[N_VAULTS];

/**
 * @brief Reset a vault to default configuration.
 * @param vault The vault to reset.
 */
static void reset_vault(vault_t *vault)
{
	vault->in_use = 0;
	vault->size = 0;
	vault->used_space = 0;
	vault->owner = -1;

	if (vault->driver != NULL) {
		cdev_del(vault->driver);
		vault->driver = NULL;
	}

	if (vault->data != NULL) {
		kfree(vault->data);
		vault->data = NULL;
	}
}

/**
 * @brief Get the current user id.
 */
static uid_t get_current_uid(void)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,14,0)
	kuid_t uid_wrapper = current_uid();
	uid_t uid = __kuid_val(uid_wrapper);
	return uid;
#else
	return 1;
#endif
}

/**
 * @brief Handler for opening a vault.
 * @details This function is called whenever `open()` is called on a vault file descriptor.
 * @param inode The inode of the resource.
 * @param file The file struct of the resource.
 * @return `0` on success, negative value otherwise.
 */
static int vault_open(struct inode *inode, struct file *file)
{
	vault_t *vault;
	int dev_idx = MINOR(inode->i_rdev);

	vault = &vaults[dev_idx];

	if (vault->owner != get_current_uid()) {
		printk("User has no permission to open this secvault.\n");
		return -EACCES;
	}

	return 0;
}

/**
 * @brief Handler for closing a vault.
 * @details This function is called whenever `close()` is called on a vault file descriptor.
 * @param inode The inode of the resource.
 * @param file The file struct of the resource.
 * @return `0` on success, negative value otherwise.
 */
static int vault_release(struct inode *inode, struct file *file)
{
	vault_t *vault;
	int dev_idx = MINOR(inode->i_rdev);

	vault = &vaults[dev_idx];

	if (vault->owner != get_current_uid()) {
		printk("User has no permission to release this secvault.\n");
		return -EACCES;
	}

	return 0;
}

/**
 * @brief Handler for seeking a vault.
 * @details This function is called whenever `seek()` is called on a vault file descriptor.
 * @param file The file struct of the resource.
 * @param offset The offset to seek.
 * @param whence The mode for seeking the file.
 * @return The new absolute offset in the file.
 */
static loff_t vault_llseek(struct file *file, loff_t offset, int whence)
{
	vault_t *vault;
	loff_t new_offset;
	int dev_idx;

	dev_idx = MINOR(file->f_inode->i_rdev);
	vault = &vaults[dev_idx];

	if (vault->owner != get_current_uid()) {
		printk("User has no permission to seek this secvault.\n");
		return -EACCES;
	}

	if (down_interruptible(&vault->sem)) {
		up(&vault->sem);
		return -ERESTARTSYS;
	}

	switch (whence) {
	case SEEK_SET:
		new_offset = offset;
		break;
	case SEEK_CUR:
		new_offset = file->f_pos + offset;
		break;
	case SEEK_END:
		new_offset = vault->size - 1 - offset;
		break;
	default:
		up(&vault->sem);
		return -EINVAL;
	}

	if (new_offset < 0 || new_offset >= vault->size) {
		up(&vault->sem);
		return -EINVAL;
	}

	file->f_pos = new_offset;

	up(&vault->sem);

	return new_offset;
}

/**
 * @brief Encrypt or decrypt a buffer using xor operation.
 * @details This function is used to encrypt and decrypt the vaults of the module.
 * @param buffer The buffer to apply this operation on.
 * @param len The length of the buffer.
 * @param offset The offset of the encryption cursor in the buffer.
 * @param key The key to encrypt the buffer with.
 */
static void xor_buffer(char *buffer, size_t len, loff_t offset, char key[KEYSIZE])
{
	int i, key_idx;

	for (i = 0; i < len; i++) {
		key_idx = (offset + i) % KEYSIZE;
		buffer[i] ^= key[key_idx];
	}
}

/**
 * @brief Read data from a secure vault.
 * @details Data is first copied into an internal buffer, decrypted and then copied to userspace.
 * @param file The file the read from.
 * @param user The buffer in userspace to read into.
 * @param len The length of the buffer to read into.
 * @param offset The offset in the file to read from.
 * @return Negative value on error, size of the data read otherwise.
 */
static ssize_t vault_read(struct file *file, char __user *user, size_t len, loff_t *offset)
{
	vault_t *vault;
	size_t not_copied;
	size_t len_avail;
	size_t to_copy;
	int dev_idx;
	char *buffer;

	dev_idx = MINOR(file->f_inode->i_rdev);
	vault = &vaults[dev_idx];

	if (vault->owner != get_current_uid()) {
		printk("User has no permission to read this secvault.\n");
		return -EACCES;
	}

	if (down_interruptible(&vault->sem)) {
		up(&vault->sem);
		return -ERESTARTSYS;
	}

	len_avail = vault->used_space - *offset;

	if (len_avail < len)
		to_copy = len_avail;
	else
		to_copy = len;

	buffer = kmalloc(to_copy * sizeof(char), GFP_KERNEL);
	if (buffer == NULL) {
		printk("Could not allocate memory to read secvault.\n");
		up(&vault->sem);
		return -ENOMEM;
	}

	memcpy(buffer, vault->data + *offset, to_copy);

	xor_buffer(buffer, to_copy, *offset, vault->key);

	not_copied = copy_to_user(user, buffer, to_copy);

	kfree(buffer);

	*offset += to_copy - not_copied;

	up(&vault->sem);

	return to_copy - not_copied;
}

/**
 * @brief Write data from a secure vault.
 * @details Data is first copied into an internal buffer from userspace, encrypted and then copied to the vault.
 * @param file The file the write into.
 * @param user The buffer in userspace to read from.
 * @param len The length of the buffer to read from.
 * @param offset The offset in the file to write into.
 * @return Negative value on error, size of the data written otherwise.
 */
static ssize_t vault_write(struct file *file, const char __user *user, size_t len, loff_t *offset)
{
	vault_t *vault;
	size_t not_copied;
	size_t len_avail;
	size_t to_copy;
	size_t max_written;
	int dev_idx;
	char *buffer;

	dev_idx = MINOR(file->f_inode->i_rdev);
	vault = &vaults[dev_idx];

	if (vault->owner != get_current_uid()) {
		printk("User has no permission to write secvault.\n");
		return -EACCES;
	}

	if (down_interruptible(&vault->sem)) {
		up(&vault->sem);
		return -ERESTARTSYS;
	}

	len_avail = vault->size - *offset;

	if (len_avail < len)
		to_copy = len_avail;
	else
		to_copy = len;

	buffer = kmalloc(to_copy * sizeof(char), GFP_KERNEL);
	if (buffer == NULL) {
		printk("Could not allocate memory to write secvault.\n");
		up(&vault->sem);
		return -ENOMEM;
	}

	not_copied = copy_from_user(buffer, user, to_copy);

	xor_buffer(buffer, to_copy, *offset, vault->key);

	// Calculate new possible used_space.
	max_written = *offset + to_copy - not_copied;

	if (max_written > vault->used_space)
		vault->used_space = max_written;

	memcpy(vault->data + *offset, buffer, to_copy);

	kfree(buffer);

	*offset += to_copy - not_copied;

	up(&vault->sem);

	return to_copy - not_copied;
}

/**
 * @brief The instructions of the vault devices.
 */
static struct file_operations vault_fops = {
	.owner = THIS_MODULE, ///< The owner of this device.
	.open = vault_open, ///< The open handler.
	.release = vault_release, ///< The close handler.
	.llseek = vault_llseek, ///< The seek handler.
	.read = vault_read, ///< The read handler.
	.write = vault_write ///< The write handler.
};

/**
 * @brief The handler for incoming ioctl requests.
 * @details This function will parse the request and handle specified instructions.
 * @param file The file this handler was called from.
 * @param cmd The command that was passed to the ioctl request.
 * @param arg The arguments for this ioctl request.
 * @return `0` on success, negative value otherwise.
 */
static long ioctl_handler(struct file *file, unsigned int cmd, unsigned long arg)
{
	int errind;
	vault_t *vault;
	struct cdev *sv_driver;

	struct msg_t msg;

	errind = copy_from_user(&msg, (void *)arg, sizeof(struct msg_t));
	if (errind < 0)
		return -EINVAL;

	msg.key[KEYSIZE] = '\0';

	if (msg.device >= N_VAULTS) {
		printk("Specified secvault does not exist.\n");
		return -EINVAL;
	}

	vault = &vaults[msg.device];

	if (down_interruptible(&vault->sem)) {
		up(&vault->sem);
		return -ERESTARTSYS;
	}

	switch (cmd) {
	case 0:
		// Handle initialization.
		printk("Creating new secvault %d, size %ld, key '%s'.\n", msg.device, msg.size, msg.key);

		if (vault->in_use) {
			printk("Specified secvault was already created.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		if (msg.size < 1 || msg.size > MAX_DATA) {
			printk("Secvault size is invalid.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		sv_driver = cdev_alloc();
		if (sv_driver == NULL) {
			printk("Allocating driver object failed.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		cdev_init(sv_driver, &vault_fops);
		sv_driver->owner = THIS_MODULE;
		vault->driver = sv_driver;

		errind = cdev_add(sv_driver, vault->number, 1);
		if (errind) {
			printk("Adding cdev failed.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		vault->data = kmalloc(msg.size * sizeof(char), GFP_KERNEL);

		if (vault->data == NULL) {
			printk("Could not allocate memory for secvault data.\n");
			up(&vault->sem);
			return -ENOMEM;
		}

		vault->in_use = 1;
		vault->size = msg.size;
		vault->used_space = 0;
		vault->owner = get_current_uid();

		memcpy(vault->key, msg.key, KEYSIZE);
		memset(vault->data, 0, vault->size);

		break;
	case 1:
		// Handle keychange.
		printk("Changing key of secvault %d to '%s'.\n", msg.device, msg.key);

		if (!vault->in_use) {
			printk("Secvault was not yet created.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		if (vault->owner != get_current_uid()) {
			printk("User not granted access due to missing permission.\n");
			up(&vault->sem);
			return -EACCES;
		}

		memcpy(vault->key, msg.key, KEYSIZE);

		break;
	case 5:
		// Handle erasure of memory.
		printk("Erasing secvault %d.\n", msg.device);

		if (!vault->in_use) {
			printk("Secvault was not yet created.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		if (vault->owner != get_current_uid()) {
			printk("User not granted access due to missing permission.\n");
			up(&vault->sem);
			return -EACCES;
		}

		vault->used_space = 0;
		memset(vault->data, 0, vault->size);

		break;
	case 3:
		// Handle deletion of vault.
		printk("Deleting secvault %d.\n", msg.device);

		if (!vault->in_use) {
			printk("Secvault was not yet created.\n");
			up(&vault->sem);
			return -EINVAL;
		}

		if (vault->owner != get_current_uid()) {
			printk("User not granted access due to missing permission.\n");
			up(&vault->sem);
			return -EACCES;
		}

		reset_vault(vault);

		break;
	default:
		printk("Received unknown ioctl 0x%x.\n", cmd);
		up(&vault->sem);
		return -EINVAL;
	}

	up(&vault->sem);

	return 0;
}

/**
 * @brief The instructions of the ioctl device.
 */
static struct file_operations ioctl_fops = {
	.owner = THIS_MODULE, ///< The owner of the device.
	.unlocked_ioctl = ioctl_handler, ///< The ioctl handler.
};

/**
 * @brief Entry point of the module.
 * @details This method is called when the module is loaded. It will set up all requried resources.
 */
static int __init mod_init(void)
{
	int errind;
	int i;
	vault_t *vault;

	memset(&vaults, 0, sizeof(vaults));

	for (i = 0; i < N_VAULTS; i++) {
		vault = &vaults[i];
		vault->data = NULL;
		vault->driver = NULL;
		vault->number = MKDEV(MAJOR_NUM, i);
		vault->in_use = 0;
		sema_init(&vault->sem, 1);
	}

	driver_class = class_create(THIS_MODULE, "secvault");

	// Register devices numbers.

	dev_numbers = MKDEV(MAJOR_NUM, 0);
	errind = register_chrdev_region(dev_numbers, 1 + N_VAULTS, MODNAME);
	if (errind < 0) {
		printk("Registering chrdev failed.\n");
		return -EIO;
	}

	// Create ioctl device.

	ioctl_number = MKDEV(MAJOR_NUM, N_VAULTS);

	ioctl_driver = cdev_alloc();
	if (ioctl_driver == NULL) {
		printk("Allocating driver object failed.\n");
		unregister_chrdev_region(dev_numbers, 1 + N_VAULTS);
		return -EIO;
	}

	cdev_init(ioctl_driver, &ioctl_fops);
	ioctl_driver->owner = THIS_MODULE;

	errind = cdev_add(ioctl_driver, ioctl_number, 1);
	if (errind) {
		printk("Adding cdev failed.\n");
		kobject_put(&ioctl_driver->kobj);
		unregister_chrdev_region(dev_numbers, 1 + N_VAULTS);
		return -EIO;
	}

	ioctl_dev = device_create(driver_class, NULL, ioctl_number, NULL, "%s", "ioctl");

	return 0;
}

/**
 * @brief Exit point of the module.
 * @details This method is called when the module is unloaded. It will clean up all allocated resources.
 */
static void __exit mod_exit(void)
{
	int i;
	vault_t *vault;

	// Cleanup vaults.

	for (i = 0; i < N_VAULTS; i++) {
		vault = &vaults[i];
		reset_vault(vault);
	}

	// Cleanup ioctl device.

	device_destroy(driver_class, ioctl_number);
	cdev_del(ioctl_driver);

	// Free devices numbers and destroy class.

	unregister_chrdev_region(dev_numbers, 1 + N_VAULTS);
	class_destroy(driver_class);

	return;
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
