# TA-mids
TA-mids 1.0.0
Mcafee Network IDS Technology Adapter
Supports all tested versions of Splunk (tested up to 6.4)
This TA accepts mcafee NSM/IDS data directly via splunk or by a syslog server

This application is primarily supported via the following methods:
https://github.com/AlaskaSSO/TA-mwg
https://answers.splunk.com/app/questions/3340.html
This is monitored by the author, and you will get a response.

This is a Splunk Technology Adapter for Mcafee Network IDS (referenced by mids in the rest of this document);  the nomenclature has changed in recent releases to be called a "splunk add-on".  This app uses the classic naming.

All you need to do ahead of time is make sure your mids logs are tagged as sourcetype=mcafee:ips OR sourcetype=mids.  There are currently two different log formats that I am aware of produced by mids, the original one which is taken care of by https://splunkbase.splunk.com/app/2735/ that reads sourcetype=mcafee:ips.  This TA handles both sourcetypes, as it aliases them together.  I noticed the original app also lost several log types as well.  (samples are in the sample directory).  My extractions also lose this data...  I don't know why but sometimes mids sends out alerts with no source or destination.  Just informational alerts that something is happening.  Very strange.

Additionally this has basic extractions for both syslogauditlogforwarder and syslogfaultforwarder, the auditing and fault logging options if enabled in Mcafee IDS.

Request:  Currently all of the log lines are being correctly identified that I have access too.  If you have a new log which is not supported, please submit them to me so I will add a extraction to this app.

Request:  I have mostly complete vendor category to category lookup;  if you have any categories which do NOT show up;  please send me the log and I can end them to the lookup table


CHANGELOG: 
Version 1.0.0
re-released under license CC BY-SA 3.0

Version 0.0.1
Initial release

-Myron
myron.davis@alaska.gov


---
File: README-inputs.txt
 
This TA-app assumes the following:

mids logs will all have sourcetype mcafee:ips or mids

This is a technology adapter that enables front end applications to view mids data via the common information model. If the front end is written to CIM standards your mids data will automatically appear in that app. Examples include Splunk Enterprise Security (and likely others).

This app provides the following common information models:
[mids]
search = sourcetype=mids mids_action="*"
#tags ids attack

I recommend adding a new port on your syslog-ng and configuring mcafee to log directly to that.  Or if the traffic is on 514 mixed in with other traffic you can split it out by using filters with syslog-ng.  OR logging directly to a index server and forcing sourcetype=mids and index=mids (or your choice.)

Sample splunk inputs.conf for your splunk forwarder on syslog-ng

[default]
host_segment = 4
[monitor:///logpartition/logs/mids/*/2016/...]
SHOULD_LINEMERGE=false
sourcetype = mids
index=mids

[monitor:///logpartition/logs/mids/*/2017/...]
SHOULD_LINEMERGE=false
sourcetype = mids
index=mids

#recommend options for high memory high throughput syslog-ng server for sysctl.conf
sysctl -w net.core.rmem_max=2147483648
sysctl -w net.ipv4.tcp_rmem='32768 2097152 1073741824'
sysctl -w net.core.netdev_max_backlog=200000


Sample options for /etc/syslog-ng/syslog-ng.conf

options { chain_hostnames(off); flush_lines(1000); use_dns(no); use_fqdn(no);
          log_fifo_size(1073741823);
          owner("root"); group("adm"); perm(0640); stats_freq(0);
          bad_hostname("^gconfd$"); threaded(yes); log_msg_size(8192);
};

#
source s_ext_udp_514 {
        udp(so_rcvbuf(1073741823) log_fetch_limit(10000));
};


#Set this to whatever hostnames correspond to your boxes
#I've ran multiple mids of different generations and they don't always send the same format in the program field
filter f_mids { match("(SyslogAlertForwarder|AlertLog:|SyslogFaultForwarder:|SyslogAuditLogForwarder:|MIDSJ|MIDSA|soassonspa45e1)" value("PROGRAM")); };
filter f_notmids { not filter(f_mids); };

#mids (mcafee ids)
log {
        source(s_ext_udp_514);
        filter(f_mids);
        destination(d_mids);
};

destination d_mids {
   file("/logpartition/logs/mids/$HOST/$YEAR/$MONTH/$DAY/mids-$FACILITY-$YEAR-$MONTH-$DAY"
   owner(root) group(adm) perm(0640) dir_perm(0751) dir_group(adm) create_dirs(yes) template("$ISODATE $HOST $MSGHDR$MSGONLY\n"));

};


