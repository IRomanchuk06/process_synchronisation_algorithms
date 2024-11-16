#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <semaphore.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>

#define SHM_NAME "/file_copy_shm"
#define SEM_READ_NAME "/sem_read"
#define SEM_WRITE_NAME "/sem_write"
#define BUFFER_SIZE 1024

void error_exit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void cleanup_resources() {
    sem_unlink(SEM_READ_NAME);
    sem_unlink(SEM_WRITE_NAME);
    shm_unlink(SHM_NAME);
}

void setup_shared_resources(int *shm_fd, void **shared_memory, sem_t **sem_read, sem_t **sem_write) {
    *sem_read = sem_open(SEM_READ_NAME, O_CREAT | O_EXCL, 0666, 1);
    *sem_write = sem_open(SEM_WRITE_NAME, O_CREAT | O_EXCL, 0666, 0);
    if (*sem_read == SEM_FAILED || *sem_write == SEM_FAILED) 
        error_exit("Failed to create semaphores");

    *shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (*shm_fd == -1) error_exit("Failed to create shared memory");

    if (ftruncate(*shm_fd, BUFFER_SIZE + sizeof(int)) == -1)
        error_exit("Failed to set shared memory size");

    *shared_memory = mmap(NULL, BUFFER_SIZE + sizeof(int), PROT_WRITE | PROT_READ, MAP_SHARED, *shm_fd, 0);
    if (*shared_memory == MAP_FAILED) error_exit("Failed to map shared memory");
}

void reader_process(const char *input_file, char *buffer, int *eof_flag, sem_t *sem_read, sem_t *sem_write) {
    FILE *file = fopen(input_file, "rb");
    if (!file) error_exit("Failed to open input file");

    while (1) {
        sem_wait(sem_read);

        size_t bytes_read = fread(buffer, 1, BUFFER_SIZE, file);
        if (ferror(file)) error_exit("Error reading file");

        *eof_flag = (bytes_read < BUFFER_SIZE) ? 1 : 0;

        sem_post(sem_write);

        if (*eof_flag) break;
    }

    fclose(file);
}

void writer_process(const char *output_file, char *buffer, int *eof_flag, sem_t *sem_read, sem_t *sem_write) {
    FILE *file = fopen(output_file, "wb");
    if (!file) error_exit("Failed to open output file");

    while (1) {
        sem_wait(sem_write);

        fwrite(buffer, 1, BUFFER_SIZE, file);
        if (ferror(file)) error_exit("Error writing to file");

        if (*eof_flag) break;

        sem_post(sem_read);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input_file> <output_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    atexit(cleanup_resources);

    sem_t *sem_read, *sem_write;
    int shm_fd;
    void *shared_memory;

    setup_shared_resources(&shm_fd, &shared_memory, &sem_read, &sem_write);

    char *buffer = (char *)shared_memory;
    int *eof_flag = (int *)(buffer + BUFFER_SIZE);

    pid_t reader_pid = fork();
    if (reader_pid == -1) error_exit("Failed to fork reader process");

    if (reader_pid == 0) {
        reader_process(argv[1], buffer, eof_flag, sem_read, sem_write);
        exit(EXIT_SUCCESS);
    }

    pid_t writer_pid = fork();
    if (writer_pid == -1) error_exit("Failed to fork writer process");

    if (writer_pid == 0) {
        writer_process(argv[2], buffer, eof_flag, sem_read, sem_write);
        exit(EXIT_SUCCESS);
    }

    int status;
    waitpid(reader_pid, &status, 0);
    waitpid(writer_pid, &status, 0);

    munmap(shared_memory, BUFFER_SIZE + sizeof(int));
    sem_close(sem_read);
    sem_close(sem_write);

    printf("File copy completed successfully.\n");
    return 0;
}
