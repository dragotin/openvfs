# openVFS - a Virtual File Sytem for Cloud Storage

openVFS is a framework to provide virtual files for the free desktop. It is based on the [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace)-filesystem layer to provide virtual files for the free desktop.

This is **experimental** code that is based on the nice work from Rémi Flament - remipouak at gmail.com called LoggedFS which is a filesystem monitoring system. This was considered useful and choosen as a base of the openVFS work.

Please feel free to create PRs or engage in the discussion.

## Simplest usage

To start the openvfs and record access to `/tmp/TEST` into `~/log.txt`, just do:

    openvfsfuse -l ~/log.txt /tmp/TEST

To stop recording, just `unmount` as usual:

    sudo umount /tmp/TEST

The `~/log.txt` file will need to be changed to readable by setting permissions:

    chmod 0666 ~/log.txt

## Installation from source

First you have to make sure that FUSE is installed on your computer.
If you have a recent distribution it should be. FUSE can be downloaded here: [github.com/libfuse/libfuse](https://github.com/libfuse/libfuse).

openVFS has the following dependencies:

    fuse
    pcre2
    libxml2

## Configuration

openvfsfuse can use an XML configuration file if you want it to log operations only for certain files, for certain users, or for certain operations.

Here is a sample configuration file :

    <?xml version="1.0" encoding="UTF-8"?>

    <loggedFS logEnabled="true" printProcessName="true">
      <includes>
        <include extension=".*" uid="*" action=".*" retname=".*"/>
      </includes>
      <excludes>
        <exclude extension=".*\.bak$" uid="*" action=".*" retname="SUCCESS"/>
        <exclude extension=".*" uid="1000" action=".*" retname="FAILURE"/>
        <exclude extension=".*" uid="*" action="getattr" retname=".*"/>
      </excludes>
    </loggedFS>

This configuration can be used to log everything except it if concerns a `*.bak` file, or if the uid is 1000, or if the operation is `getattr`.

## Launching openvfsfuse

If you just want to test openvfsfuse you don't need any configuration file.

Just use that command:

    openvfsfuse -f -p /var

You should see logs like these :

    tail -f /var/log/syslog
    2018-03-21 15:32:14,095 INFO [default] LoggedFS not running as a daemon
    2018-03-21 15:32:14,095 INFO [default] LoggedFS running as a public filesystem
    2018-03-21 15:32:14,095 INFO [default] LoggedFS starting at /var.
    2018-03-21 15:32:14,095 INFO [default] chdir to /var
    2018-03-21 15:32:15,375 INFO [default] getattr /var/ {SUCCESS} [ pid = 934 /usr/sbin/VBoxService uid = 0 ]
    2018-03-21 15:32:15,375 INFO [default] getattr /var/run {SUCCESS} [ pid = 934 /usr/sbin/VBoxService uid = 0 ]
    2018-03-21 15:32:15,376 INFO [default] readlink /var/run {SUCCESS} [ pid = 934 /usr/sbin/VBoxService uid = 0 ]
    2018-03-21 15:32:15,376 INFO [default] readlink /var/run {SUCCESS} [ pid = 934 /usr/sbin/VBoxService uid = 0 ]
    2018-03-21 15:32:15,890 INFO [default] getattr /var/cache {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,891 INFO [default] getattr /var/cache/apt {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,891 INFO [default] getattr /var/cache/apt/archives {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,891 INFO [default] getattr /var/cache/apt/archives/partial {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,891 INFO [default] getattr /var/cache/apt/archives/partial {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,892 INFO [default] getattr /var/lib {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,892 INFO [default] getattr /var/lib/apt {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,892 INFO [default] getattr /var/lib/apt/lists {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,892 INFO [default] getattr /var/lib/apt/lists/partial {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:15,892 INFO [default] getattr /var/lib/apt/lists/partial {SUCCESS} [ pid = 1539 update-notifier uid = 1000 ]
    2018-03-21 15:32:17,873 INFO [default] LoggedFS closing.

If you have a configuration file to use you should use this command:

    ./openvfsfuse -c openvfsfuse.xml -p /var

If you want to log what other users do on your filesystem, you should use the `-p` option to allow them to see your mounted files. For a complete documentation see the manual page.

