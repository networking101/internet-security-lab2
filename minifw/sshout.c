#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops sshOutFilterHook;

unsigned int sshOutFilter(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(22)
	&& (unsigned int)((unsigned char *)&iph->daddr)[0] == 10
	&& (unsigned int)((unsigned char *)&iph->daddr)[1] == 0
	&& (unsigned int)((unsigned char *)&iph->daddr)[2] == 2
	&& (unsigned int)((unsigned char *)&iph->daddr)[3] == 5) {
    printk(KERN_INFO "Dropping SSH packet to %d.%d.%d.%d\n",
        ((unsigned char *)&iph->daddr)[0],
        ((unsigned char *)&iph->daddr)[1],
        ((unsigned char *)&iph->daddr)[2],
        ((unsigned char *)&iph->daddr)[3]);
    return NF_DROP;
  } else {
    return NF_ACCEPT;
  }
}


int setUpFilter(void) {
        printk(KERN_INFO "Registering a SSH filter.\n");
        sshOutFilterHook.hook = sshOutFilter; 
        sshOutFilterHook.hooknum = NF_INET_POST_ROUTING;
        sshOutFilterHook.pf = PF_INET;
        sshOutFilterHook.priority = NF_IP_PRI_FIRST;

        // Register the hook.
        nf_register_hook(&sshOutFilterHook);
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "SSH filter is being removed.\n");
        nf_unregister_hook(&sshOutFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");


