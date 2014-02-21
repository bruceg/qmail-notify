#!/bin/bash
setup() {
    rm -f $tmp/{run,out,qmail}
    mkdir $tmp/run
    mkdir $tmp/out

    export QMAILHOME=$tmp/qmail
    mkdir -p $QMAILHOME/{bin,control,queue/{info,mess,local,remote}/0}
    cat >$QMAILHOME/bin/qmail-inject <<EOF
#!/bin/sh
cat > $tmp/out/$$
EOF
    chmod +x $QMAILHOME/bin/*

    for n in 0 1
    do
	printf "Fsender$n@example.com\\0" > $QMAILHOME/queue/info/0/$n
	printf "Trecip$n@example.com\\0" > $QMAILHOME/queue/remote/0/$n
	cat >$QMAILHOME/queue/mess/0/$n <<EOF
From: <sender$n@example.com>
To: <recip$n@example.com>
Subject: Test $n

Testing $n
EOF
    done
    echo 86400 > $QMAILHOME/control/queuelifetime
    echo host.name.com > $QMAILHOME/control/me
}

notify() {
    $src/qmail-notify -T $tmp/run/qmail-notify.time
}
