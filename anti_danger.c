#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/list.h>

#define MODULE_NAME "anti_danger"
#define PROTECT_DIR_NAME "anti_danger"

// ==================== 1. execve 拦截 (发现危险指令，直接杀死发起进程) ====================
static int execve_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->regs[0];
    const char __user *const __user *argv = (const char __user *const __user *)regs->regs[1];
    char k_filename[256] = {0};
    
    if (!filename || strncpy_from_user(k_filename, filename, sizeof(k_filename) - 1) <= 0)
        return 0;

    char *base_name = strrchr(k_filename, '/');
    base_name = base_name ? base_name + 1 : k_filename;

    if (strcmp(base_name, "rm") == 0 || strcmp(base_name, "dd") == 0) {
        char arg[256] = {0};
        int is_danger = 0;
        for (int i = 1; i < 5; i++) {
            const char __user *arg_ptr = NULL;
            if (get_user(arg_ptr, &argv[i]) || !arg_ptr) break;
            if (strncpy_from_user(arg, arg_ptr, sizeof(arg) - 1) <= 0) continue;

            if (strcmp(base_name, "rm") == 0) {
                if (strstr(arg, "-rf") || strstr(arg, "-fr") || 
                   (strstr(arg, "-r") && i > 1) || (strstr(arg, "-f") && i > 1)) {
                    is_danger = 1; break;
                }
            } else if (strcmp(base_name, "dd") == 0) {
                if (strncmp(arg, "of=/dev/block", 13) == 0 || strncmp(arg, "of=/dev/sd", 10) == 0) {
                    is_danger = 1; break;
                }
            }
        }
        if (is_danger) {
            // 【安全版逻辑】：拦截并杀掉发起命令的进程，不关机
            pr_emerg("[anti_danger] ALERT! Dangerous command '%s' blocked. Killing process.\n", base_name);
            send_sig(SIGKILL, current, 1); 
            return 1; // 阻止原系统调用继续执行
        }
    }
    return 0;
}
static struct kprobe kp_execve = { .symbol_name = "__arm64_sys_execve", .pre_handler = execve_pre_handler };

// ==================== 2. ksud 删除拦截 (保护自身目录) ====================
static bool is_from_ksud(void) {
    if (strcmp(current->comm, "ksud") == 0) return true;
    if (current->real_parent && strcmp(current->real_parent->comm, "ksud") == 0) return true;
    return false;
}

static bool is_protected_target(struct dentry *dentry) {
    if (!dentry) return false;
    struct dentry *parent = dentry->d_parent;
    for (int i = 0; i < 3 && parent; i++) {
        if (strcmp(parent->d_name.name, PROTECT_DIR_NAME) == 0) return true;
        parent = parent->d_parent;
    }
    return false;
}

struct unlink_data { bool intercept; };

static int unlink_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct unlink_data *data = (struct unlink_data *)ri->data;
    data->intercept = false;
    struct dentry *dentry = (struct dentry *)regs->regs[2]; 
    
    if (is_from_ksud() && is_protected_target(dentry)) {
        data->intercept = true;
        pr_emerg("[anti_danger] Blocked ksud from deleting protected file!\n");
    }
    return 0;
}

static int unlink_return_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct unlink_data *data = (struct unlink_data *)ri->data;
    if (data->intercept) {
        regs->regs[0] = -EPERM; // 强行修改返回值，拒绝删除
    }
    return 0;
}

static struct kretprobe krp_unlink = {
    .kp.symbol_name = "vfs_unlink",
    .entry_handler = unlink_entry_handler,
    .handler = unlink_return_handler,
    .data_size = sizeof(struct unlink_data),
    .maxactive = 64,
};

static struct kretprobe krp_rmdir = {
    .kp.symbol_name = "vfs_rmdir",
    .entry_handler = unlink_entry_handler,
    .handler = unlink_return_handler,
    .data_size = sizeof(struct unlink_data),
    .maxactive = 64,
};

// ==================== 3. 防卸载 ====================
static int delete_module_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct unlink_data *data = (struct unlink_data *)ri->data;
    data->intercept = false;
    const char __user *name_user = (const char __user *)regs->regs[0];
    char k_name[256] = {0};
    
    if (name_user && strncpy_from_user(k_name, name_user, sizeof(k_name) - 1) > 0) {
        if (strcmp(k_name, MODULE_NAME) == 0) {
            data->intercept = true;
            pr_emerg("[anti_danger] Blocked attempt to unload module!\n");
        }
    }
    return 0;
}

static struct kretprobe krp_delete = {
    .kp.symbol_name = "__arm64_sys_delete_module",
    .entry_handler = delete_module_entry_handler,
    .handler = unlink_return_handler,
    .data_size = sizeof(struct unlink_data),
    .maxactive = 16,
};

// ==================== 4. 模块隐藏 ====================
static void hide_module(void) {
    list_del(&THIS_MODULE->list);
    if (THIS_MODULE->mkobj.kobj.state_initialized) {
        kobject_del(&THIS_MODULE->mkobj.kobj);
    }
}

// ==================== 5. 注册与退出 ====================
static int __init anti_danger_init(void) {
    if (register_kprobe(&kp_execve) < 0) return -1;
    if (register_kretprobe(&krp_unlink) < 0) return -1;
    if (register_kretprobe(&krp_rmdir) < 0) return -1;
    if (register_kretprobe(&krp_delete) < 0) return -1;
    hide_module();
    pr_info("[anti_danger] Safe version loaded & hidden.\n");
    return 0;
}

static void __exit anti_danger_exit(void) {
    unregister_kprobe(&kp_execve);
    unregister_kretprobe(&krp_unlink);
    unregister_kretprobe(&krp_rmdir);
    unregister_kretprobe(&krp_delete);
}

module_init(anti_danger_init);
module_exit(anti_danger_exit);
MODULE_LICENSE("GPL");