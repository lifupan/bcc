#!/usr/bin/python
#
# tcpv4connect	Trace TCP IPv4 connect()s.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpv4connect [-h] [-t] [-p PID]
#
# This is provided as a basic example of TCP connection & socket tracing.
#
# All IPv4 connection attempts are traced, even if they ultimately fail.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 15-Oct-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sockios.h>
#include <uapi/linux/if.h>
#include <linux/fs.h>
#include <bcc/proto.h>

BPF_HASH(currsock, u32, unsigned long);

int kprobe__sock_ioctl(struct pt_regs *ctx, struct file *file, unsigned cmd, unsigned long arg)
{
        if (cmd != SIOCGIFCONF ) {
	  //  bpf_trace_printk("trace_sock_ioctl cmd=%d\\n", cmd);
            return 0;
        }

//	bpf_trace_printk("trace_sock_ioctl cmd-SIOCGIFCONF=%d\\n", cmd);
	u32 pid = bpf_get_current_pid_tgid();

	// stash the sock ptr for lookup on return
	currsock.update(&pid, &arg);

	return 0;
};

int kretprobe__sock_ioctl(struct pt_regs *ctx)
{
	int ret = PT_REGS_RC(ctx);
	u32 pid = bpf_get_current_pid_tgid();

        unsigned long *arg;
	arg = currsock.lookup(&pid);
	if (arg == NULL) {
		return 0;	// missed entry
	}

        struct ifconf ifc;

        bpf_probe_read_user(&ifc, sizeof(ifc), (const void *)*arg);
        ifc.ifc_len -= sizeof(struct ifreq);

	// output
        char *ifreq_p;
        ifreq_p = (char *)ifc.ifc_buf;
        ifreq_p += ifc.ifc_len;
   //     struct ifreq req;
  //      memset(&req, 0, sizeof(req));

  //      bpf_probe_write_user(ifreq_p, &req, sizeof(req));


        int retn = bpf_probe_write_user((void *)*arg, &ifc, sizeof(ifc));

	bpf_trace_printk("trace_sock_ioctl %d, %d, %d\\n", ifc.ifc_len, sizeof(struct ifreq), retn);

	currsock.delete(&pid);

	return 0;
}
"""

# initialize BPF
b = BPF(text=bpf_text)

# header
print("%-6s %-12s %-16s %-16s %-4s" % ("PID", "COMM", "SADDR", "DADDR",
    "DPORT"))

def inet_ntoa(addr):
	dq = b''
	for i in range(0, 4):
		dq = dq + str(addr & 0xff).encode()
		if (i != 3):
			dq = dq + b'.'
		addr = addr >> 8
	return dq

# filter and format output
while 1:
	# Read messages from kernel pipe
	try:
	    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
	#    (_tag, saddr_hs, daddr_hs, dport_s) = msg.split(b" ")
	except ValueError:
	    # Ignore messages from other tracers
	    continue
	except KeyboardInterrupt:
	    exit()

        print(msg)
