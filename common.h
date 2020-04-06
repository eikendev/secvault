/**
 * @file
 * @author eikendev
 * @date 2018-01-16
 * @brief This module contains common declarations of the project.
 * @details Common declarations include the number of vaults and structs to handle ioctl calls.
 */

#ifndef __COMMON_H__
#define __COMMON_H__

/**
 * @brief The number of vaults to use.
 */
#define N_VAULTS 4

/**
 * @brief The size of the key used to encrypt the vaults.
 */
#define KEYSIZE 10

/**
 * @brief The maximum size of a vault in bytes.
 */
#define MAX_DATA 1048576

/**
 * @brief Types of ioctl commands for the client.
 */
enum vault_cmd {
	CREATE, ///< Create the vault.
	CHANGE_KEY, ///< Change the encryption key of the vault.
	ERASE, ///< Erase the vault.
	DELETE ///< Delete the vault.
};

/**
 * @brief Struct of an ioctl message.
 */
struct msg_t {
	char key[KEYSIZE + 1]; ///< Key used to encrypt the vault.
	unsigned long size; ///< Size of the vault.
	unsigned int device; ///< Identification number of the vault.
};

#endif
