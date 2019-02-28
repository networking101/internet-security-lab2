#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetInFilterHook;

unsigned int telnetInFilter(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
  struct iphdr *iph;
  struct tcphdr *tcph;

  iph = ip_hdr(skb);
  tcph = (void *)iph+iph->ihl*4;

  if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23)
	&& (unsigned int)((unsigned char *)&iph->saddr)[0] == 10
	&& (unsigned int)((unsigned char *)&iph->saddr)[1] == 0
	&& (unsigned int)((unsigned char *)&iph->saddr)[2] == 2
	&& (unsigned int)((unsigned char *)&iph->saddr)[3] == 5) {
    printk(KERN_INFO "Dropping telnet packet from %d.%d.%d.%d\n",
        ((unsigned char *)&iph->saddr)[0],
        ((unsigned char *)&iph->saddr)[1],
        ((unsigned char *)&iph->saddr)[2],
        ((unsigned char *)&iph->saddr)[3]);
    return NF_DROP;
  } else {
    return NF_ACCEPT;
  }
}


int setUpFilter(void) {
        printk(KERN_INFO "Registering a Telnet filter.\n");
        telnetInFilterHook.hook = telnetInFilter; 
        telnetInFilterHook.hooknum = NF_INET_PRE_ROUTING;
        telnetInFilterHook.pf = PF_INET;
        telnetInFilterHook.priority = NF_IP_PRI_FIRST;

        // Register the hook.
        nf_register_hook(&telnetInFilterHook);
        return 0;
}

void removeFilter(void) {
        printk(KERN_INFO "Telnet filter is being removed.\n");
        nf_unregister_hook(&telnetInFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");


