#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

struct xmp_state {
    char *keyphrase;
    char *rootdir;
    FILE *logfile;
};

#define XMP_DATA ((struct xmp_state *) fuse_get_context()->private_data)
#define XATTR_USER_PREFIX "user.pa5-encfs."
#define XATTR_USER_PREFIX_LEN (sizeof (XATTR_USER_PREFIX) - 1)
#define XATTR_ENCRYPTED_POSTFIX "encrypted"
#define XATTR_KEYPHRASE_POSTFIX "keyphrase"

FILE *log_open()
{
    FILE *logfile;
    
    // very first thing, open up the logfile and mark that we got in
    // here.  If we can't open the logfile, we're dead.
    logfile = fopen("logfile.log", "w");
    if (logfile == NULL) {
	perror("logfile");
	exit(EXIT_FAILURE);
    }
    
    // set logfile to line buffering
    setvbuf(logfile, NULL, _IOLBF, 0);

    return logfile;
}

void log_msg(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    vfprintf(XMP_DATA->logfile, format, ap);
}

int isEncrypted(char* fpath){
	int res = 0;
	
	char* fullAttr = malloc(strlen(XATTR_ENCRYPTED_POSTFIX) + XATTR_USER_PREFIX_LEN + 1);
	strcpy(fullAttr, XATTR_USER_PREFIX);
	strcat(fullAttr, XATTR_ENCRYPTED_POSTFIX);
	char* response = (char*) malloc(5);
	int numresponse = getxattr(fpath, fullAttr, response, 5);
	log_msg("getxattr response: %i %s\n", numresponse, response);
	
	if(strcmp(response, "true") == 0){
		res = 1;
	}
	
	return res;
}

int isKeyphrase(char* fpath){
	int res = 0;
	
	char* fullAttr = malloc(strlen(XATTR_KEYPHRASE_POSTFIX) + XATTR_USER_PREFIX_LEN + 1);
	strcpy(fullAttr, XATTR_USER_PREFIX);
	strcat(fullAttr, XATTR_KEYPHRASE_POSTFIX);
	char* response = (char*) malloc(50);
	int numresponse = getxattr(fpath, fullAttr, response, 50);
	log_msg("getxattr response: %i %s\n", numresponse, response);
	
	if(strcmp(response, XMP_DATA->keyphrase) == 0){
		res = 1;
	}
	
	return res;
}

char* buf_crypt(const char* inbuf, int inlen, int* outlen, int action, char* key_str){
    int tmplen;
    unsigned char* tmpbuf = (unsigned char*) malloc(inlen + EVP_MAX_BLOCK_LENGTH);
   	char* outbuf = (char*) malloc(inlen + EVP_MAX_BLOCK_LENGTH);

    /* OpenSSL libcrypto vars */
    EVP_CIPHER_CTX ctx;
    unsigned char key[32];
    unsigned char iv[32];
    int nrounds = 5;
    
    /* tmp vars */
    int i;

    /* Setup Encryption Key and Cipher Engine */
	if(!key_str){
	    /* Error */
	    fprintf(stderr, "Key_str must not be NULL\n");
	    return 0;
	}
	
	/* Build Key from String */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
			   (unsigned char*)key_str, strlen(key_str), nrounds, key, iv);
	if (i != 32) {
	    /* Error */
	    fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
	    return 0;
	}
	
	/* Init Engine */
	EVP_CIPHER_CTX_init(&ctx);
	//Action 1 = encrypt, 0 = decrypt
	EVP_CipherInit_ex(&ctx, EVP_aes_256_cbc(), NULL, key, iv, action);   
	
	log_msg("Input Buffer: %s\nInput Length: %i\n", inbuf, inlen);
	
	/* perform cipher transform on block */
    if(!EVP_CipherUpdate(&ctx, tmpbuf, &tmplen, (const unsigned char*) inbuf, inlen))
	{
	    /* Error */
	    EVP_CIPHER_CTX_cleanup(&ctx);
	    return 0;
	}
	
	log_msg("Temp Buffer: %s\nTemp Length: %i\n", tmpbuf, tmplen);
	
	/* Write Block */
	memcpy(outbuf, tmpbuf, tmplen);
	log_msg("where1");
	*outlen = tmplen;

	/* Handle remaining cipher block + padding */
	if(!EVP_CipherFinal_ex(&ctx, tmpbuf, &tmplen))
	    {
		/* Error */
		log_msg("where");
		EVP_CIPHER_CTX_cleanup(&ctx);
		return 0;
	    }
	/* Write remainign cipher block + padding*/
	log_msg("where2");
	memcpy(outbuf + *outlen, tmpbuf, tmplen);
	*outlen += tmplen;

	log_msg("Out Buffer: %s\nOut Length: %i\n", outbuf, *outlen);
	
	//EVP_CIPHER_CTX_cleanup(&ctx);
	
    /* Success */
    return outbuf;
}


static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, XMP_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("GettAttr: %s\n", fpath);
	
	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Access: %s\n", fpath);
	
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("ReadLink: %s\n", fpath);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Read Dir: %s\n", fpath);

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Mknode: %s\n", fpath);
	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("MkDir: %s\n", fpath);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Unlink: %s\n", fpath);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Rm Dir: %s\n", fpath);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	char flink[PATH_MAX];
	xmp_fullpath(flink, to);
	log_msg("Symlink: %s\n", flink);

	res = symlink(from, flink);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	
	char fpath[PATH_MAX];
	char fnewpath[PATH_MAX];
	xmp_fullpath(fpath, from);
	xmp_fullpath(fnewpath, to);
	
	log_msg("Rename: %s\n", fpath);

	res = rename(fpath, fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;
	
	char fpath[PATH_MAX], fnewpath[PATH_MAX];
	xmp_fullpath(fpath, from);
	xmp_fullpath(fnewpath, to);
	
	log_msg("Link: %s\n", fpath);

	res = link(fpath,fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Chmod: %s\n", fpath);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Chown: %s\n", fpath);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Truncate: %s\n", fpath);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("uTimes: %s\n", fpath);

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Open: %s\n", fpath);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}


static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Read: %s %i\n", path, size);
	
	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;
		
	log_msg("File Size: %i\n", res);
	
	if(res > 0 && isEncrypted(fpath) && isKeyphrase(fpath)){
		log_msg("%s is encrypted", fpath);
 		int outlen;
		char* decryptBuffer = buf_crypt(buf, res, &outlen, 0, XMP_DATA->keyphrase);
		log_msg("Decrypt Buff: %s %i\n", decryptBuffer, outlen);
		buf = realloc(buf, outlen);
		memcpy(buf, decryptBuffer, outlen);
		size = outlen;
		log_msg("Final Buff: %s\n", buf);
	}

	close(fd);
	return size;
}


static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	(void) size;
	(void) offset;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	
	fd = open(fpath, O_WRONLY);
	if (fd == -1)
		return -errno;
	log_msg("Write: %s %i\n", buf, size);
	
	if(isEncrypted(fpath)){
		log_msg("%s is encrypted", fpath);
		int bufSize;
		char *encryptBuffer = buf_crypt(buf, size, &bufSize, 1, XMP_DATA->keyphrase);
		log_msg("Encryption Success: %s\n", encryptBuffer);
		res = pwrite(fd, encryptBuffer, bufSize, 0);
	}else{
		res = pwrite(fd, buf, size, 0);
	}
	
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Statfs: %s\n", fpath);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;
    
    char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("Create: %s\n", fpath);

    int res;
    res = creat(fpath, mode);
    if(res == -1)
	return -errno;
	
	//Set Xattr Encrypted
	char* encryptAttr = malloc(strlen(XATTR_ENCRYPTED_POSTFIX) + XATTR_USER_PREFIX_LEN + 1);
	strcpy(encryptAttr, XATTR_USER_PREFIX);
	strcat(encryptAttr, XATTR_ENCRYPTED_POSTFIX);
	char* val = "true";
	log_msg("%s\n", encryptAttr);
	int result = setxattr(fpath, encryptAttr, val, 5, 0);
	
	if(result == -1){
		log_msg("Unable to set Xattr\n");
		return -errno;
	}
	
	//SET XAttr Key
	char* keyAttr = malloc(strlen(XATTR_KEYPHRASE_POSTFIX) + XATTR_USER_PREFIX_LEN + 1);
	strcpy(keyAttr, XATTR_USER_PREFIX);
	strcat(keyAttr, XATTR_KEYPHRASE_POSTFIX);
	log_msg("%s\n", keyAttr);
	result = setxattr(fpath, keyAttr, XMP_DATA->keyphrase, strlen(XMP_DATA->keyphrase), 0);
	
	if(result == -1){
		log_msg("Unable to set Xattr\n");
		return -errno;
	}
	log_msg("Xattr encrypted set\n");
	log_msg("encrypted: %i\n", isEncrypted(fpath));

    close(res);

    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("SetXAttr: %s\n", fpath);
	
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("GetxAttr: %s\n", fpath);
	
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("ListxAttr: %s\n", fpath);
	
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	log_msg("RemovexAttr: %s\n", fpath);
	
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create     = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

//Key Phrase Mirror Directory Mount Point
int main(int argc, char *argv[])
{
	struct xmp_state *xmp_data;
	
	if(argc < 2){
		printf("Key Phrase Required!\n");
		exit(0);
	}else if(argc < 3){
		printf("Mirror Directory Required!\n");
		exit(0);
	}else if(argc < 4){
		printf("Mount Point Required!\n");
		exit(0);
	}else{
		xmp_data = malloc(sizeof(struct xmp_state));
		if (xmp_data == NULL){
			perror("main calloc");
			abort();
		}
		
		xmp_data->rootdir = realpath(argv[argc - 2], NULL);
		xmp_data->keyphrase = argv[argc - 3];
    	argv[argc - 3] = argv[argc - 1];
    	argc -= 2;
	}
	xmp_data->logfile = log_open();
	
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, xmp_data);
}





