rule SSH_One_Malware
{
    meta:
        description = "Detects the ssh-one backdoor script"
        author = "South Udan Cybersecurity Team"
        date = "2025-06-03"
        threat_level = 5

    strings:
        $a = "darkl0rd.com:7758"
        $b = "/tmp/SSH-One"
        $c = "chkconfig iptables off"
        $d = "wget $hfs_s"
        $e = "/etc/rc.local"

    condition:
        all of ($a, $b, $c, $e)
}

