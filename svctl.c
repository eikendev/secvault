/**
 * @file
 * @author eikendev
 * @date 2018-01-16
 * @brief This module contains the control program for the kernel module.
 * @details The control program is used to set up, delete and erase vaults.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/ioctl.h>

#include "common.h"

/**
 * @brief The path where the ioctl device can be found.
 */
#define SV_CTL "/dev/sv_ctl"

/**
 * @brief The name of the program.
 */
static char *progname;

/**
 * @brief The file descriptor of the ioctl device.
 */
static int ctl_fd = -1;

/**
 * @brief Struct used to store current program configuration.
 */
typedef struct {
	enum vault_cmd cmd; ///< The command that was selected.
	unsigned long size; ///< The size of the vault to be created.
	unsigned int vault_id; ///< The id of the specified vault.
} options_t;

/**
 * @brief Print a usage message.
 * @details The function terminates the program with the value `EXIT_FAILURE`. The global variable `progname` has to be defined in order for this function to work.
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s [-c <size>|-k|-e|-d] <secvault id>\n", progname);
	fprintf(stderr, "  <size> must be a positive number.\n");
	fprintf(stderr, "  <secvault id> must specify a valid secvault.\n");
	exit(EXIT_FAILURE);
}

/**
 * @brief Parse the arguments passed as program arguments.
 * @details Program parsing conforms to POSIX standard.
 * @param argc The program argument vector length.
 * @param argv The program argument vector.
 * @param options The struct in which to store the configuration in.
 */
static void parse_arguments(int argc, char *argv[], options_t *options)
{
	opterr = 0;

	bool parsed_cmd = false;

	int c;
	while ((c = getopt(argc, argv, "c:ked")) != -1) {
		if (parsed_cmd)
			usage();

		parsed_cmd = true;

		switch (c) {
		case 'c':
			options->cmd = CREATE;
			char *endptr;
			long int size = strtol(optarg, &endptr, 10);

			if (*endptr != '\0')
				usage();

			if (size < 1 || size > MAX_DATA)
				usage();

			options->size = size;
			break;
		case 'k':
			options->cmd = CHANGE_KEY;
			break;
		case 'e':
			options->cmd = ERASE;
			break;
		case 'd':
			options->cmd = DELETE;
			break;
		default:
			usage();
		}
	}

	// we need exactly one command
	if (!parsed_cmd)
		usage();

	// we need the secvault id
	if (argc - optind != 1)
		usage();

	char *endptr;
	long int vault_id = strtol(argv[optind], &endptr, 10);

	if (*endptr != '\0')
		usage();

	if (vault_id < 0 || vault_id > UINT_MAX || vault_id >= N_VAULTS)
		usage();

	options->vault_id = vault_id;
}

/**
 * @brief Read a key from the user.
 * @details Wait for the user to input a key and store in the specified buffer.
 * @param buffer The buffer to store the key in.
 */
static void read_user_key(char *buffer) {
	char *line = NULL;
	size_t len_alloc = 0;
	ssize_t len_line = getline(&line, &len_alloc, stdin);

	if (len_line == -1) {
		fprintf(stderr, "[%s] ERROR: could not read input\n", progname);

		if (line != NULL)
			free(line);

		exit(EXIT_FAILURE);
	} else if (len_line - 1 > KEYSIZE) {
		fprintf(stderr, "[%s] ERROR: key must be at most ten characters long\n", progname);

		if (line != NULL)
			free(line);

		exit(EXIT_FAILURE);
	}

	memset(buffer, 0x0, KEYSIZE);
	memcpy(buffer, line, len_line - 1);

	if (line != NULL)
		free(line);
}

/**
 * @brief Create a new vault.
 * @details Requests a new vault from the ioctl device.
 * @param vault_id The id of the vault to create.
 * @param size The maximum size of the vault.
 */
static void sv_create(uint8_t vault_id, uint16_t size)
{
	int errind;

	struct msg_t msg;
	msg.device = vault_id;
	msg.size = size;

	printf("Encryption key: ");
	fflush(stdout);
	read_user_key(msg.key);

	errind = ioctl(ctl_fd, 0, &msg);
	if (errind == -1) {
		fprintf(stderr, "[%s] ERROR: ioctl failed: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief Change the key of the specified vault.
 * @details Requests a key from the user and modifies the vault accordingly.
 * @param vault_id The id of the vault to alter.
 */
static void sv_change_key(uint8_t vault_id)
{
	int errind;

	struct msg_t msg;
	msg.device = vault_id;

	printf("Encryption key: ");
	fflush(stdout);
	read_user_key(msg.key);

	errind = ioctl(ctl_fd, 1, &msg);
	if (errind == -1) {
		fprintf(stderr, "[%s] ERROR: ioctl failed: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief Erase the specified vault.
 * @details Resets content of the vault.
 * @param vault_id The id of the vault to erase.
 */
static void sv_erase(uint8_t vault_id)
{
	int errind;

	struct msg_t msg;
	msg.device = vault_id;

	errind = ioctl(ctl_fd, 5, &msg);
	if (errind == -1) {
		fprintf(stderr, "[%s] ERROR: ioctl failed: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief Delete the specified vault.
 * @details Tell the ioctl device to delete the vault. Stored data will be lost.
 * @param vault_id The id of the vault to delete.
 */
static void sv_delete(uint8_t vault_id)
{
	int errind;

	struct msg_t msg;
	msg.device = vault_id;

	errind = ioctl(ctl_fd, 3, &msg);
	if (errind == -1) {
		fprintf(stderr, "[%s] ERROR: ioctl failed: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}
}

/**
 * @brief The entry point of the program.
 * @details This function is called upon program start. First, arguments will be parsed. Then, actions are performed to ensure execution of specified user instructions.
 * @param argc The program argument vector length.
 * @param argv The program argument vector.
 */
int main(int argc, char *argv[])
{
	progname = argv[0];

	options_t options;
	memset(&options, 0, sizeof(options));
	parse_arguments(argc, argv, &options);

	ctl_fd = open(SV_CTL, O_RDWR);
	if (ctl_fd < 0) {
		fprintf(stderr, "[%s] ERROR: open failed: %s\n", progname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	switch (options.cmd) {
	case CREATE:
		sv_create(options.vault_id, options.size);
		break;
	case CHANGE_KEY:
		sv_change_key(options.vault_id);
		break;
	case ERASE:
		sv_erase(options.vault_id);
		break;
	case DELETE:
		sv_delete(options.vault_id);
		break;
	default:
		assert(false);
	}

	return EXIT_SUCCESS;
}
