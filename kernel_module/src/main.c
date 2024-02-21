#include "main.h"

#include <linux/module.h>
#include <net/genetlink.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Neil SAUVAGE");
MODULE_DESCRIPTION("ExecGuard Module");

int gnl_cmd_send_pid_doit(struct sk_buff *sender_skb, struct genl_info *info);

#define GNL_OPS_LEN (GNL_COMMAND_COUNT)

struct genl_ops gnl_ops[GNL_OPS_LEN] = {
    {
        .cmd = GNL_C_SEND_PID,
        .flags = 0,
        .internal_flags = 0,
        .doit = gnl_cmd_send_pid_doit,
        .dumpit = NULL,
        .start = NULL,
        .done = NULL,
        .validate = 0,
    }
};

static struct nla_policy gnl_policy[GNL_ATTRIBUTE_ENUM_LEN] = {
    [GNL_A_UNSPEC] = {.type = NLA_UNSPEC},
    [GNL_A_PID] = {.type = NLA_U32}
};

static struct genl_family gnl_family = {
    .id = 0,
    .hdrsize = 0,
    .name = FAMILY_NAME,
    .version = 1,
    .ops = gnl_ops,
    .n_ops = GNL_OPS_LEN,
    .policy = gnl_policy,
    .maxattr = GNL_ATTRIBUTE_ENUM_LEN,
    .module = THIS_MODULE,
    .parallel_ops = 0,
    .netnsok = 0,
    .pre_doit = NULL,
    .post_doit = NULL,
};

int gnl_cmd_send_pid_doit(struct sk_buff *sender_skb, struct genl_info *info) {

    if (info == NULL) {
        pr_err("An error occurred in %s():\n", __func__);
        return -EINVAL;
    }

    struct nlattr *na = info->attrs[GNL_A_PID];

    if (!na) {
        pr_err("no info->attrs[%i]\n", GNL_A_PID);
        return -EINVAL;
    }

    pid_t *res = nla_data(na);
    if (!res)
        pr_err("error while receiving data\n");
    else
        pr_info("received: '%d'\n", *res);

    return 0;
}

static int __init execguard_module_init(void) {
    pr_info("ExecGuard Module inserted.\n");

    int rc = genl_register_family(&gnl_family);
    if (rc) {
        pr_err("FAILED: genl_register_family(): %i\n", rc);
        pr_err("An error occurred while inserting the generic netlink example module\n");
        return -1;
    } else {
        pr_info("successfully registered custom Netlink family '" FAMILY_NAME "' using Generic Netlink.\n");
    }
    return 0;
}

static void __exit execguard_module_exit(void) {
    pr_info("ExecGuard Module unloaded.\n");

    int ret = genl_unregister_family(&gnl_family);
    if (ret != 0) {
        pr_err("genl_unregister_family() failed: %i\n", ret);
        return;
    } else {
        pr_info("successfully unregistered custom Netlink family '" FAMILY_NAME "' using Generic Netlink.\n");
    }
}

module_init(execguard_module_init);
module_exit(execguard_module_exit);
