# Detect is it Docker execution or not
docker = file('/.dockerenv').exist?
vbox = file('/var/log/vboxadd-setup.log').exist?

control 'local-timezone' do
  impact 1.0
  title  'timezone'
  desc   'Check UTC'
  # Check timezone
  describe command('date') do
    its('stdout') { should match(/UTC/) }
  end
end

control 'local-repos' do
  impact 1.0
  title  'repositories'
  desc   'Check active YUM repositories'

  only_if do
    file('/etc/yum.repos.d/CentOS-Base.repo').exist?
  end
  # Check our repos
  %w[base epel extras updates].each do |repo|
    describe yum.repo(repo) do
      it { should exist }
      it { should be_enabled }
    end
  end
end

control 'local-packages' do
  impact 1.0
  title  'packages'
  desc   'check whether or not basic packages are installed'
  # Confirm our packages ares installed
  %w[epel-release deltarpm rng-tools sysstat].each do |pkg|
    describe package(pkg) do
      it { should be_installed }
    end
  end
  if os[:name] != 'amazon' && (os[:family] == 'redhat' && os[:release].start_with?('6'))
    %w[ntp ntpdate].each do |pkg|
      describe package(pkg) do
        it { should be_installed }
      end
    end
  end
end

control 'local-services' do
  impact 1.0
  title  'packages'
  desc   'check whether or not basic daemon are enabled/disabled'
  # Check our enabled services
  if os[:name] != 'amazon' && (os[:family] == 'redhat' && os[:release].start_with?('6'))
    %w[ntpd ntpdate].each do |srv|
      describe service(srv) do
        it { should be_enabled }
      end
    end
  end
  describe service('rngd') do
    it { should be_enabled }
  end

  # Check our disabled services
  %w[kdump mdmonitor netconsole psacct nfs racoon rdisc saslauthd].each do |srv|
    describe service(srv) do
      it { should_not be_enabled } || it { should_not be_installed }
    end
  end
end

control 'local-entropy' do
  impact 1.0
  title  'entropy'
  desc   'Check for high-quality RNG'

  only_if { !docker }

  # Check rngd config
  describe file('/etc/sysconfig/rngd') do
    it { should be_file }
    its('content') { should match(/--rng-device=drng/) }
  end

  # Check entropy thresholds
  describe kernel_parameter('kernel.random.read_wakeup_threshold') do
    its('value') { should eq 1024 }
  end
  describe kernel_parameter('kernel.random.write_wakeup_threshold') do
    its('value') { should eq 3072 }
  end
end

control 'local-cloud-config' do
  impact 1.0
  title 'cloud-init'
  desc  'Check cloud-init config presence'

  only_if do
    command('cloud-init').exist?
  end

  describe file('/etc/cloud/cloud.cfg.d/99_local.cfg') do
    it { should be_file }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'local-packages-arch' do
  impact 1.0
  title 'arch'
  desc  'Check package architecture'
  describe command('rpm -qa | grep -q 686$') do
    its('stderr') { should eq '' }
    its('exit_status') { should eq 1 }
  end
end

control 'eap-directories' do
  impact 1.0
  title  'eap directories'
  desc   'check if all necessary files are present'

  describe directory('/usr/local/sbin') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end
end

control 'eap-files' do
  impact 1.0
  title  'eap files'
  desc   'check if all necessary files are present'

  describe file('/lib64/security/eap_mfa.so') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end
  describe file('/usr/local/sbin/pam.py') do
    it { should exist }
    its('mode') { should cmp '0700' }
  end
  describe file('/usr/local/sbin/cleanUsers.py') do
    it { should exist }
    its('mode') { should cmp '0700' }
  end
  describe file('/usr/local/sbin/eapaddgroup.sh') do
    it { should exist }
    its('mode') { should cmp '0700' }
  end
  describe file('/etc/exclude_users') do
    it { should exist }
    its('mode') { should cmp '0644' }
    its('content') { should match(/idxsvc/) }
    its('content') { should match(/centos/) }
    its('content') { should match(/sync/) }
  end
  describe file('/etc/eapserver') do
    it { should exist }
    its('mode') { should cmp '0644' }
  end
  describe file('/etc/pam.d/eap-q') do
    it { should exist }
    its('mode') { should cmp '0644' }
  end
end

control 'eap_mfa_so' do
  impact 1.0
  title  'eap_mfa.so file is linked'
  desc   'check if eap_mfa.so file is linked in the following files'

  %w[etc/pam.d/sshd etc/pam.d/sudo etc/pam.d/su etc/pam.d/eap-q].each do |ftc|
    describe file("/#{ftc}") do
      it { should exist }
      its('content') { should match(/eap_mfa.so/) }
    end
  end
end

control 'sudoers' do
  impact 1.0
  title  'check sudoers'
  desc   '/etc/group and /etc/sudoers should contain sudoergroup string'

  describe file('/etc/sudoers.d/sudoergroup') do
    it { should exist }
    its('content') { should match(/%sudoergroup/) }
  end
  describe file('/etc/group') do
    its('content') { should match(/sudoergroup:x:680006:/) }
  end
end

control 'cert-check' do
  impact 1.0
  title  'check dj cert'
  desc   'ensure DJ cert is present in correct location'

  describe file '/etc/pki/ca-trust/source/anchors/djca-2048.pem' do
    it { should exist }
    its('owner') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'proto-disable' do
  impact 1.0
  title  'disable unused protocols'
  desc   'disable this protocols to improve security'

  %w[dccp sctp rds tipc].each do |proto|
    describe file('/etc/modprobe.d/CIS.conf') do
      it { should exist }
      its('owner') { should eq 'root' }
      its('mode') { should cmp '0644' }
      its('content') { should  match %r{install #{proto} \/bin\/true} }
    end
  end
end

control 'cron-mode' do
  impact 1.0
  title  'check cron mode'
  desc   'mode should equal 0700 for dirs and 0600 for files'

  %w[cron.hourly cron.daily cron.weekly cron.monthly cron.d].each do |cron|
    describe file("/etc/#{cron}") do
      its('mode') { should cmp '0700' }
    end
  end
  %w[anacrontab crontab].each do |crontab|
    describe file("/etc/#{crontab}") do
      its('mode') { should cmp '0600' }
    end
  end
end

control 'newrelic' do
  impact 1.0
  title  'newrelic installed'
  desc   'check if newrelic is installed'

  describe command('newrelic-infra') do
    it { should exist }
  end
  describe service('newrelic-infra') do
    # should be_disabled/be_stopped doesn't work here
    it { should_not be_enabled }
    it { should_not be_running }
  end
  describe user('newrelic_infra') do
    it { should exist }
    its('group') { should eq 'newrelic_infra' }
  end
end

control 'crowdstrike' do
  impact 1.0
  title  'crowdstrike installed'
  desc   'check if crowdstrike is installed/enabled/running'

  only_if { !docker }
  only_if { !vbox }

  describe service('falcon-sensor') do
    # should be_enabled/be_started doesn't work here
    it { should be_enabled }
    it { should be_running }
  end
end

control 'djstamp' do
  impact 1.0
  title  'DJ stamp'
  desc   'DJ stamp is stored in /etc/cloudops.dat created by Packer'

  describe file('/etc/cloudops.dat') do
    it { should exist }
    its('mode') { should cmp '0400' }
  end
  only_if { !docker }
  only_if { !vbox }
end

control 'dj-repos' do
  impact 1.0
  title  'dj-repos'
  desc   'check if DJ repositories enabled'

  if os[:name] == 'centos'
    %w[A-centos-base A-centos-updates A-epel-base dj-tools docker djif-artifactory].each do |repo|
      describe yum.repo(repo) do
        it { should exist }
        it { should be_enabled }
      end
    end
  elsif os[:name] == 'rhel'
    %w[djif-artifactory dj-tools].each do |repo|
      describe yum.repo(repo) do
        it { should exist }
        it { should be_enabled }
      end
    end
  elsif os[:name] == 'amazon'
    %w[djif-artifactory A-centos-base A-centos-updates A-epel-base dj-tools].each do |repo|
      describe yum.repo(repo) do
        it { should exist }
        it { should be_enabled }
      end
    end
  end
end

control 'splunk' do
  impact 1.0
  title  'splunk install'
  desc   'check if splunk is installed correctly'

  describe file('/opt/splunkforwarder/bin/scripts/checkSplunkForwarder.py') do
    it { should exist }
    its('mode') { should cmp '0755' }
  end

  describe file('/opt/splunkforwarder/bin/splunk') do
    it { should be_executable }
  end
end

control 'issue-files' do
  impact 1.0
  title  'issue files'
  desc   'ensure the issue files are present'

  %w[issue issue.net].each do |issuefile|
    describe file "/etc/#{issuefile}" do
      it { should exist }
      its('owner') { should eq 'root' }
      its('mode') { should cmp '0644' }
    end
  end
end

control 'tanium-client' do
  impact 1.0
  title  'tanium client'
  desc   'ensure it is installed and enabled'

  describe package('TaniumClient') do
    it { should be_installed }
  end
  describe file('/opt/Tanium/TaniumClient/TaniumClient') do
    it { should be_executable }
  end

  describe directory('/opt/Tanium/TaniumClient/Tools/') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0755' }
  end

  describe file('/opt/Tanium/TaniumClient/README') do
    it { should exist }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
    its('mode') { should cmp '0644' }
  end
end

control 'ena-kernel-module' do
  impact 1.0
  title 'ENA kernel module test'
  desc 'ensure ENA kernel module is enabled'

  describe kernel_module('ena') do
    it { should be_loaded }
    it { should_not be_disabled }
    it { should_not be_blacklisted }
  end
  only_if { !docker }
end

# include_controls 'linux-baseline' do
include_controls 'dj-linux-baseline' do
  # os-05: Check login.defs
  # On this this is expected that UID_MIN and UID_MAX will  equal  1000.
  # This is correct statement for  centos-7, but not  for  centos-6. For
  # centos-7 minimal IDs  for  users  and  groups should start from 500.
  # Of cource we can  enforce  these IDs to any values that we want, but
  # for centos-6 the  first  user on the system (i.e. vagrant) will have
  # that values set to  500, that will fail the check. Moreover, several
  # CIS statements (i.e. 5.4.2)  expect  UID  set  to 500. So we need to
  # modify 'os-05' check to suit for both centos-6 and centos-7 systems.
  # Duplicate required variables from origin check
  login_defs_umask = attribute('login_defs_umask', default: os.redhat? ? '077' : '027', description: 'Default umask to set in login.defs')
  login_defs_passmaxdays = attribute('login_defs_passmaxdays', default: '60', description: 'Default password maxdays to set in login.defs')
  login_defs_passmindays = attribute('login_defs_passmindays', default: '7', description: 'Default password mindays to set in login.defs')
  login_defs_passwarnage = attribute('login_defs_passwarnage', default: '7', description: 'Default password warnage (days) to set in login.defs')

  # Set custom variable
  min_id = os[:name] != 'amazon' && (os[:family] == 'redhat' && os[:release].start_with?('7')) ? '1000' : '500'

  # Finally run the check
  control 'os-05' do
    impact 1.0
    title 'Check login.defs'
    desc 'Check owner and permissions for login.defs. Also check the configured PATH variable and umask in login.defs'
    describe file('/etc/login.defs') do
      it { should exist }
      it { should be_file }
      it { should be_owned_by 'root' }
      its('group') { should eq 'root' }
      it { should_not be_executable }
      it { should be_readable.by('owner') }
      it { should be_readable.by('group') }
      it { should be_readable.by('other') }
    end
    describe login_defs do
      its('ENV_SUPATH') { should include('/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') }
      its('ENV_PATH') { should include('/usr/local/bin:/usr/bin:/bin') }
      its('UMASK') { should include(login_defs_umask) }
      its('PASS_MAX_DAYS') { should eq login_defs_passmaxdays }
      its('PASS_MIN_DAYS') { should eq login_defs_passmindays }
      its('PASS_WARN_AGE') { should eq login_defs_passwarnage }
      its('LOGIN_RETRIES') { should eq '5' }
      its('LOGIN_TIMEOUT') { should eq '60' }
      its('UID_MIN') { should eq min_id }
      its('GID_MIN') { should eq min_id }
    end
  end

  # To satisfy this check, sysctl part  of  os-hardening cookbook should be
  # executed, but it's not applicable for containers, so it must be skipped.
  # https://github.com/dev-sec/chef-os-hardening/blob/e497d988af0642fc08ab863abf0c1aed9757ce17/recipes/default.rb#L38
  # os-10: CIS: Disable unused filesystems
  control 'os-10' do
    only_if { !docker }
  end

  # Docker is required to have IP forwarding enabled
  # sysctl-01: IPv4 Forwarding
  control 'sysctl-01' do
    only_if { !docker && !service('docker').installed? }
  end

  # Here is a  bunch  of  sysctl  checks  that should not be executed in case of
  # containerized execution, but for AWS instances Inspec detects virtualization
  # system as xen,  instead  of  Docker,  so  skip  doesn't  work  as  expected.
  # https://github.com/dev-sec/linux-baseline/blob/master/controls/sysctl_spec.rb#L45
  # Should be skipped 33 sysctl check, but as far  as  our goal to cover as many
  # checks as possible, we will skip only failing  check,  which can't be fixed:
  if docker
    skip_control 'sysctl-05'
    skip_control 'sysctl-06'
    skip_control 'sysctl-07'
    skip_control 'sysctl-10'
    skip_control 'sysctl-11'
    skip_control 'sysctl-14'
    skip_control 'sysctl-18'
    skip_control 'sysctl-19'
    skip_control 'sysctl-20'
    skip_control 'sysctl-21'
    skip_control 'sysctl-22'
    skip_control 'sysctl-23'
    skip_control 'sysctl-24'
    skip_control 'sysctl-25'
    skip_control 'sysctl-26'
    skip_control 'sysctl-27'
    skip_control 'sysctl-28'
    skip_control 'sysctl-30'
  end
end

# Include CIS controls, unnecessary checks skipped
include_controls 'cis-dil-benchmark' do
  # Skip check /tmp mount
  # cis-dil-benchmark-1.1.2: Ensure separate partition exists for /tmp
  # cis-dil-benchmark-1.1.3: Ensure nodev option set on /tmp partition
  # cis-dil-benchmark-1.1.4: Ensure nosuid option set on /tmp partition
  # cis-dil-benchmark-1.1.5: Ensure noexec option set on /tmp partition
  skip_control 'cis-dil-benchmark-1.1.2'
  skip_control 'cis-dil-benchmark-1.1.3'
  skip_control 'cis-dil-benchmark-1.1.4'
  skip_control 'cis-dil-benchmark-1.1.5'

  # Skip check /var mount
  # cis-dil-benchmark-1.1.6: Ensure separate partition exists for /var
  # cis-dil-benchmark-1.1.7: Ensure separate partition exists for /var/tmp
  # cis-dil-benchmark-1.1.8: Ensure nodev option set on /var/tmp partition
  # cis-dil-benchmark-1.1.9: Ensure nosuid options set on /var/tmp partition
  # cis-dil-benchmark-1.1.10: Ensure noexec option set on /var/tmp partition
  # cis-dil-benchmark-1.1.11: Ensure separate partition exists for /var/log
  # cis-dil-benchmark-1.1.12: Ensure separate partition exists in /var/log/audit
  skip_control 'cis-dil-benchmark-1.1.6'
  skip_control 'cis-dil-benchmark-1.1.7'
  skip_control 'cis-dil-benchmark-1.1.8'
  skip_control 'cis-dil-benchmark-1.1.9'
  skip_control 'cis-dil-benchmark-1.1.10'
  skip_control 'cis-dil-benchmark-1.1.11'
  skip_control 'cis-dil-benchmark-1.1.12'

  # Skip check /home mount
  # cis-dil-benchmark-1.1.13: Ensure separate partition exists for /home
  # cis-dil-benchmark-1.1.14: Ensure nodev option set on /home partition
  skip_control 'cis-dil-benchmark-1.1.13'
  skip_control 'cis-dil-benchmark-1.1.14'

  # Skip check /dev/shm mount
  # cis-dil-benchmark-1.1.15: Ensure nodev option set on /dev/shm partition
  # cis-dil-benchmark-1.1.16: Ensure nosuid option set on /dev/shm partition
  # cis-dil-benchmark-1.1.17: Ensure noexec option set on /dev/shm partition
  skip_control 'cis-dil-benchmark-1.1.15'
  skip_control 'cis-dil-benchmark-1.1.16'
  skip_control 'cis-dil-benchmark-1.1.17'

  # Docker images have grub files empty or not exist at all
  # cis-dil-benchmark-1.4.1: Ensure permissions on bootloader config are configured
  control 'cis-dil-benchmark-1.4.1' do
    only_if { !docker }
  end

  # cis-dil-benchmark-1.4.2: Ensure bootloader password is set
  # Skip setting bootloader password
  skip_control 'cis-dil-benchmark-1.4.2'

  # cis-dil-benchmark-1.5.2: Ensure XD/NX support is enabled
  # Skip it for now since CPU hardward relate check
  skip_control 'cis-dil-benchmark-1.5.2'

  # Skip this checks for Amazon Linux instance has to be rebooted
  # to set  SELinux  status  to 'enabled' and mode to  'enforcing'.
  # This also can be skipped for Docker instances.
  # cis-dil-benchmark-1.6.1.2: Ensure the SELinux state is enforcing
  control 'cis-dil-benchmark-1.6.1.2' do
    only_if { os[:name] != 'amazon' && !docker }
  end

  # cis-dil-benchmark-1.6.1.3: Ensure SELinux policy is configure
  # Need to modify this control due to differences between centos-6 and centos-7
  # Command 'sestatus' should return different lines:
  # "Policy from config file: targeted" - for centos-6
  # "Loaded policy name: targeted" - for centos-7
  # Skip this check for Amazon Linux instance has to be rebooted
  # to set SELinux  status  to 'enabled' and mode to  'enforcing'
  control 'cis-dil-benchmark-1.6.1.3' do
    title 'Ensure SELinux policy is configured'
    desc  "Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.\n\nRationale: Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met."
    impact 1.0

    tag cis: 'distribution-independent-linux:1.6.1.3'
    tag level: 2

    only_if do
      (package('selinux').installed? || command('sestatus').exist?) && os[:name] != 'amazon' && !docker
    end

    describe file('/etc/selinux/config') do
      its(:content) { should match(/^SELINUXTYPE=(targeted|mls)\s*(?:#.*)?$/) }
    end

    if os[:release].start_with?('7')
      describe command('sestatus') do
        its(:stdout) { should match(/Loaded policy name:\s+(targeted|mls)/) }
      end
    else
      describe command('sestatus') do
        its(:stdout) { should match(/Policy from config file:\s+(targeted|mls)/) }
      end
    end
  end

  # cis-dil-benchmark-1.6.1.6: Ensure no unconfined daemons exist
  # Skip because of the local VBoxService service, will add it in the local control
  skip_control 'cis-dil-benchmark-1.6.1.6'

  # Skip cis-dil-benchmark-2.2.1.2: Ensure ntp is configured
  # Since it meet the requirement in http://obmyaeceh.bkt.clouddn.com/CIS_CentOS_Linux_6_Benchmark_v2.0.1.pdf
  skip_control 'cis-dil-benchmark-2.2.1.2'

  # cis-dil-benchmark-2.2.1.3: Ensure chrony is configured
  # Modify cis-dil-benchmark-2.2.1.3 since centos7 chrony.conf location is /etc/chrony.conf instead of /etc/chrony/chrony.conf
  control 'cis-dil-benchmark-2.2.1.3' do
    title 'Ensure chrony is configured'
    desc  "chrony is a daemon which implements the Network Time Protocol (NTP) is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on chrony can be found at http://chrony.tuxfamily.org/. chrony can be configured to be a client and/or a server.\n\nRationale: If chrony is in use on the system proper configuration is vital to ensuring time synchronization is working properly.\nThis recommendation only applies if chrony is in use on the system."
    impact 1.0

    tag cis: 'distribution-independent-linux:2.2.1.3'
    tag level: 1

    only_if do
      package('chrony').installed? || command('chronyd').exist?
    end

    describe file('/etc/chrony.conf') do
      its(:content) { should match(/^server\s+\S+/) }
    end

    describe processes('chronyd') do
      its(:users) { should cmp 'chrony' }
    end
  end

  # cis-dil-benchmark-2.2.7: Ensure NFS and RPC are not enabled
  # Modify cis-dil-benchmark-2.2.7 since centos7 /usr/lib/systemd/system/rpcbind.service has Also= in the install section
  # And is-enabled shows indirect instead of disabled
  # https://www.freedesktop.org/software/systemd/man/systemctl.html
  control 'cis-dil-benchmark-2.2.7' do
    title 'Ensure NFS and RPC are not enabled'
    desc  "The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.\n\nRationale: If the system does not export NFS shares or act as an NFS client, it is recommended that these services be disabled to reduce remote attack surface."
    impact 1.0

    tag cis: 'distribution-independent-linux:2.2.7'
    tag level: 1

    %w[nfs-kernel-server nfs].each do |s|
      describe service(s) do
        it { should_not be_enabled }
        it { should_not be_running }
      end
    end

    describe service('rpcbind') do
      it { should_not be_running }
    end
  end

  # Docker is required to have IP forwarding enabled
  # cis-dil-benchmark-3.1.1: Ensure IP forwarding is disabled
  control 'cis-dil-benchmark-3.1.1' do
    only_if { !docker && !service('docker').installed? }
  end

  # We can skip this for Docker, because /etc/group/group.conf is emply for
  # containers and some sysctl params is not designed to work with  Docker.
  # cis-dil-benchmark-3.2.2: Ensure ICMP redirects are not accepted
  # cis-dil-benchmark-3.2.8: Ensure TCP SYN Cookies is enabled
  # cis-dil-benchmark-3.3.1: Ensure IPv6 router advertisements are not accepted
  # cis-dil-benchmark-3.3.2: Ensure IPv6 redirects are not accepted
  if docker
    skip_control 'cis-dil-benchmark-3.2.2'
    skip_control 'cis-dil-benchmark-3.2.8'
    skip_control 'cis-dil-benchmark-3.3.1'
    skip_control 'cis-dil-benchmark-3.3.2'
  end

  # The control can be skipped because this functionality is covered
  # via sysctl.  Please see detailed comment in cis_dil_benchmark.rb
  #
  # Skip cis-dil-benchmark-3.3.3: Ensure IPv6 is disabled
  # Need to modify this control due to differences between centos-6 and centos-7
  # Grub configuration file:
  # "/boot/grub/grub.conf" - for centos-6
  # "/boot/grub2/grub.conf" - for centos-7
  # Added file path for centos-7 to default loop.
  # control 'cis-dil-benchmark-3.3.3' do
  #   title 'Ensure IPv6 is disabled'
  #   desc  "Although IPv6 has many advantages over IPv4, few organizations have implemented IPv6.\n\nRationale: If IPv6 is not to be used, it is recommended that it be disabled to reduce the attack surface of the system."
  #   impact 0.0

  #   tag cis: 'distribution-independent-linux:3.3.3'
  #   tag level: 1

  #   only_if { !docker }

  #   describe.one do
  #     %w[/boot/grub/grub.conf /boot/grub/grub.cfg /boot/grub/menu.lst /boot/boot/grub/grub.conf /boot/boot/grub/grub.cfg /boot/boot/grub/menu.lst /boot/grub2/grub.cfg].each do |f|
  #       describe file(f) do
  #         its(:content) { should match(/ipv6\.disable=1/) }
  #       end
  #     end
  #   end
  # end
  skip_control 'cis-dil-benchmark-3.3.3'

  # cis-dil-benchmark-3.6.2: Ensure default deny firewall policy
  # Skip INPUT and OUTPUT DROP policy because the other rules
  skip_control 'cis-dil-benchmark-3.6.2'

  # cis-dil-benchmark-3.6.5: Ensure firewall rules exist for all open ports
  # Added firewall rule for port ssh and skip other listening ports
  # We can add the firewall rules on the provisioning time
  skip_control 'cis-dil-benchmark-3.6.5'

  # cis-dil-benchmark-4.1.1.2: Ensure system is disabled when audit logs are full
  # Skip this since it conflict with linux-baseline profile
  skip_control 'cis-dil-benchmark-4.1.1.2'

  # cis-dil-benchmark-4.1.12: Ensure use of privileged commands is collected
  # Skip this for now since it need to add it dynamically
  skip_control 'cis-dil-benchmark-4.1.12'

  # Auditd doesn't work on Docker containers
  # cis-dil-benchmark-4.1.2: Ensure auditd service is enabled
  # cis-dil-benchmark-4.1.3: Ensure auditing for processes that start prior to auditd is enabled
  if docker
    skip_control 'cis-dil-benchmark-4.1.2'
    skip_control 'cis-dil-benchmark-4.1.3'
  end

  # cis-dil-benchmark-4.2.1.4: Ensure rsyslog is configured to send logs to a remote log host
  # Skip this for now and will do it on application level
  skip_control 'cis-dil-benchmark-4.2.1.4'
  # cis-dil-benchmark-4.2.4: Ensure permissions on all logfiles are configured
  # Skip in amazon ecs image since can not change /var/log/ecs/ecs-agent.log.xxxx-xx-xx-xx logs permission
  # Inside of Kitchen, CI should skip cis-dil-benchmark-4.2.4 for file /var/log/vboxadd-setup.log*
  # These tests should be skipped on local run as new files are created with incorrect rights after log rotates
  # These files are only created during local run, so there is no influence when running against EC2
  control 'cis-dil-benchmark-4.2.4' do
    only_if { os[:name] != 'amazon' }
    only_if { !vbox }
  end

  # cis-dil-benchmark-5.1.8: Ensure at/cron is restricted to authorized users
  # Skip this due to dokken validation failure because of this check
  skip_control 'cis-dil-benchmark-5.1.8' if docker

  # cis-dil-benchmark-5.2.15: Ensure SSH access is limited
  # Skip this because we are not sure what user/group need to be blocked or allowed for now
  skip_control 'cis-dil-benchmark-5.2.15'

  # cis-dil-benchmark-5.3.1: Ensure password creation requirements are configured
  # Need to modify this control because default check expect one space (" ")
  # between words in required files, but os-hardening coookbook has nice tabulated
  # template. So we need to modify regexps to match that strings. Except of this,
  # for centos-6 and centos-7 here is a different ways of configuring password policy, so
  # we need to change this as well. Requirements for this control realized in 2 places:
  # default.rb and cis_dil_benchmark.tb
  control 'cis-dil-benchmark-5.3.1' do
    title 'Ensure password creation requirements are configured'
    desc "The pam_cracklib.so module checks the strength of passwords. It performs checks such as making sure a password is not a dictionary word, it is a certain length, contains a mix of characters (e.g. alphabet, numeric, other) and more. The following are definitions of the pam_cracklib.so options.\n\n* try_first_pass - retrieve the password from a previous stacked PAM module. If not available, then prompt the user for a password.\n* retry=3 - Allow 3 tries before sending back a failure.\n* minlen=14 - password must be 14 characters or more\n* dcredit=-1 - provide at least one digit\n* ucredit=-1 - provide at least one uppercase character\n* ocredit=-1 - provide at least one special character\n* lcredit=-1 - provide at least one lowercase character\n\nThe pam_pwquality.so module functions similarly but the minlen , dcredit , ucredit , ocredit , and lcredit parameters are stored in the /etc/security/pwquality.conf file. The settings shown above are one possible policy. Alter these values to conform to your own organization's password policies.\n\nRationale: Strong passwords protect systems from being hacked through brute force methods."
    impact 1.0

    tag cis: 'distribution-independent-linux:5.3.1'
    tag level: 1

    if os[:name] != 'amazon' && (os[:family] == 'redhat' && os[:release].start_with?('6'))
      if package('cracklib').installed?
        describe.one do
          %w[common-password system-auth].each do |f|
            describe file("/etc/pam.d/#{f}") do
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*try_first_pass/) }
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*retry=[3210]/) }
            end
          end
        end

        describe.one do
          %w[common-password system-auth].each do |f|
            describe file("/etc/pam.d/#{f}") do
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*minlen=(1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)/) }
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*dcredit=-[1-9][0-9]*\s*(?:#.*)?/) }
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*lcredit=-[1-9][0-9]*\s*(?:#.*)?/) }
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*ucredit=-[1-9][0-9]*\s*(?:#.*)?/) }
              its(:content) { should match(/^password(\s+)+(required|requisite)(\s+)+pam_cracklib\.so (\S+\s+)*ocredit=-[1-9][0-9]*\s*(?:#.*)?/) }
            end
          end
        end
      end
    end

    if package('pam_passwdqc').installed? || package('libpwquality').installed?
      describe.one do
        %w[common-password system-auth].each do |f|
          describe file("/etc/pam.d/#{f}") do
            its(:content) { should match(/^password(\s+)+requisite(\s+)+pam_pwquality\.so (\S+\s+)*retry=[3210]/) }
            its(:content) { should match(/^password(\s+)+requisite(\s+)+pam_pwquality\.so (\S+\s+)*try_first_pass/) }
          end
        end
      end

      describe file('/etc/security/pwquality.conf') do
        its(:content) { should match(/^minlen = (1[4-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\s*(?:#.*)?$/) }
        its(:content) { should match(/^dcredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
        its(:content) { should match(/^lcredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
        its(:content) { should match(/^ucredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
        its(:content) { should match(/^ocredit = -[1-9][0-9]*\s*(?:#.*)?$/) }
      end
    end
  end

  # cis-dil-benchmark-5.3.3: Ensure password reuse is limited
  # Need to modify this control because default check expect one space (" ")
  # between words in required files, but os-hardening coookbook has nice tabulated
  # template. So we need to modify regexps to match that strings. Requirements
  # for this control realized in 2 places: default.rb and cis_dil_benchmark.tb
  control 'cis-dil-benchmark-5.3.3' do
    title 'Ensure password reuse is limited'
    desc  "The /etc/security/opasswd file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords.\n\nRationale: Forcing users not to reuse their past 5 passwords make it less likely that an attacker will be able to guess the password. Note that these change only apply to accounts configured on the local system."
    impact 0.0

    tag cis: 'distribution-independent-linux:5.3.3'
    tag level: 1

    describe.one do
      %w[common-password system-auth].each do |f|
        describe file("/etc/pam.d/#{f}") do
          its(:content) { should match(/^password(\s+)+sufficient(\s+)+pam_unix\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
        end

        describe file("/etc/pam.d/#{f}") do
          its(:content) { should match(/^password(\s+)+required(\s+)+pam_pwhistory\.so (\S+\s+)*remember=([56789]|[1-9][0-9]+)/) }
        end
      end
    end
  end

  # cis-dil-benchmark-5.4.1.1: Ensure password expiration is 90 days or less
  # cis-dil-benchmark-5.4.1.2: Ensure minimum days between password changes is 7 or more
  # cis-dil-benchmark-5.4.1.3: Ensure password expiration warning days is 7 or more
  # cis-dil-benchmark-5.4.1.4: Ensure inactive password lock is 30 days or less
  unless file('/tmp/cis/password_expiration').exist?
    skip_control 'cis-dil-benchmark-5.4.1.1'
    skip_control 'cis-dil-benchmark-5.4.1.2'
    skip_control 'cis-dil-benchmark-5.4.1.3'
    skip_control 'cis-dil-benchmark-5.4.1.4'
  end

  # cis-dil-benchmark-5.4.4: Ensure default user umask is 027 or more restrictive
  # Skip it since it's not a good check
  skip_control 'cis-dil-benchmark-5.4.4'

  # For running integration tests on Docker, we are using kitchen-dokken driver
  # which shares kitchen folder with container instead  of  baking  appropriate
  # files during each Docker build. Here is info from dokken documentation:
  # "It makes /opt/kitchen and /opt/verifier available for mounting by the runner."
  # https://github.com/someara/kitchen-dokken
  # So we need to modify the check to exclude that files from check list.
  # cis-dil-benchmark-6.1.11: Ensure no unowned files or directories exist
  # cis-dil-benchmark-6.1.12: Ensure no ungrouped files or directories exist
  control 'cis-dil-benchmark-6.1.11' do
    title 'Ensure no unowned files or directories exist'
    desc "Sometimes when administrators delete users from the password file they neglect to remove all files owned by those users from the system.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.11'
    tag level: 1

    check_str = "df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -nouser"
    check_str += ' | grep -v "/opt/kitchen\|/opt/verifier"' if docker
    describe command(check_str) do
      its(:stdout) { should eq '' }
    end
  end

  control 'cis-dil-benchmark-6.1.12' do
    title 'Ensure no ungrouped files or directories exist'
    desc "Sometimes when administrators delete users or groups from the system they neglect to remove all files owned by those users or groups.\n\nRationale: A new user who is assigned the deleted user's user ID or group ID may then end up \"owning\" these files, and thus have more access on the system than was intended."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.12'
    tag level: 1

    check_str = "df --local -P | awk '{ if (NR!=1) print $6 }' | xargs -I '{}' find '{}' -xdev -nogroup"
    check_str += ' | grep -v "/opt/kitchen\|/opt/verifier"' if docker
    describe command(check_str) do
      its(:stdout) { should eq '' }
    end
  end

  # Skip /etc/shadow check because os hardening change the mode to 0000 for rhel
  # https://github.com/dev-sec/chef-os-hardening/blob/master/recipes/minimize_access.rb#L34
  skip_control 'cis-dil-benchmark-6.1.3'

  # Patch permissions according to CIS in outdated checks.
  # For CIS links please follow  to  cis_dil_benchmark.rb
  # cis-dil-benchmark-6.1.3: Ensure permissions on /etc/shadow are configured
  # cis-dil-benchmark-6.1.5: Ensure permissions on /etc/gshadow are configured
  # cis-dil-benchmark-6.1.6: Ensure permissions on /etc/passwd- are configured
  # cis-dil-benchmark-6.1.7: Ensure permissions on /etc/shadow- are configured
  # cis-dil-benchmark-6.1.8: Ensure permissions on /etc/group- are configured
  # cis-dil-benchmark-6.1.9: Ensure permissions on /etc/gshadow- are configured
  control 'cis-dil-benchmark-6.1.3' do
    title 'Ensure permissions on /etc/shadow are configured'
    desc "The /etc/shadow file is used to store the information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/shadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/shadow file (such as expiration) could also be useful to subvert the user accounts."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.3'
    tag level: 1

    shadow_files = ['/etc/shadow']
    shadow_files << '/usr/share/baselayout/shadow' if file('/etc/nsswitch.conf').content =~ /^shadow:\s+(\S+\s+)*usrfiles/

    expected_gid = 0
    expected_gid = 42 if os.debian?

    shadow_files.each do |f|
      describe file(f) do
        it { should exist }
        it { should_not be_readable.by 'owner' }
        it { should_not be_writable.by 'owner' }
        it { should_not be_executable.by 'owner' }
        it { should_not be_readable.by 'group' }
        it { should_not be_writable.by 'group' }
        it { should_not be_executable.by 'group' }
        it { should_not be_readable.by 'other' }
        it { should_not be_writable.by 'other' }
        it { should_not be_executable.by 'other' }
        its(:uid) { should cmp 0 }
        its(:gid) { should cmp expected_gid }
        its(:sticky) { should equal false }
        its(:suid) { should equal false }
        its(:sgid) { should equal false }
      end
    end
  end

  control 'cis-dil-benchmark-6.1.5' do
    title 'Ensure permissions on /etc/gshadow are configured'
    desc "The /etc/gshadow file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: If attackers can gain read access to the /etc/gshadow file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the /etc/gshadow file (such as group administrators) could also be useful to subvert the group."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.5'
    tag level: 1

    gshadow_files = ['/etc/gshadow']
    gshadow_files << '/usr/share/baselayout/gshadow' if file('/etc/nsswitch.conf').content =~ /^gshadow:\s+(\S+\s+)*usrfiles/

    expected_gid = 0
    expected_gid = 42 if os.debian?

    gshadow_files.each do |f|
      describe file(f) do
        it { should exist }
        it { should_not be_readable.by 'owner' }
        it { should_not be_writable.by 'owner' }
        it { should_not be_executable.by 'owner' }
        it { should_not be_readable.by 'group' }
        it { should_not be_writable.by 'group' }
        it { should_not be_executable.by 'group' }
        it { should_not be_readable.by 'other' }
        it { should_not be_writable.by 'other' }
        it { should_not be_executable.by 'other' }
        its(:uid) { should cmp 0 }
        its(:gid) { should cmp expected_gid }
        its(:sticky) { should equal false }
        its(:suid) { should equal false }
        its(:sgid) { should equal false }
      end
    end
  end

  control 'cis-dil-benchmark-6.1.6' do
    title 'Ensure permissions on /etc/passwd- are configured'
    desc "The /etc/passwd- file contains backup user account information.\n\nRationale: It is critical to ensure that the /etc/passwd- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.6'
    tag level: 1

    describe file('/etc/passwd-') do
      it { should exist }
      it { should be_readable.by 'owner' }
      it { should be_writable.by 'owner' }
      it { should_not be_executable.by 'owner' }
      it { should be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
      its(:uid) { should cmp 0 }
      its(:gid) { should cmp 0 }
      its(:sticky) { should equal false }
      its(:suid) { should equal false }
      its(:sgid) { should equal false }
    end
  end

  control 'cis-dil-benchmark-6.1.7' do
    title 'Ensure permissions on /etc/shadow- are configured'
    desc "The  /etc/shadow-  file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/shadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.7'
    tag level: 1

    describe file('/etc/shadow-') do
      it { should exist }
      it { should_not be_readable.by 'owner' }
      it { should_not be_writable.by 'owner' }
      it { should_not be_executable.by 'owner' }
      it { should_not be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should_not be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
      its(:uid) { should cmp 0 }
      its(:gid) { should cmp 0 }
      its(:sticky) { should equal false }
      its(:suid) { should equal false }
      its(:sgid) { should equal false }
    end
  end

  control 'cis-dil-benchmark-6.1.8' do
    title 'Ensure permissions on /etc/group- are configured'
    desc "The /etc/group- file contains a backup list of all the valid groups defined in the system.\n\nRationale: It is critical to ensure that the /etc/group- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.8'
    tag level: 1

    describe file('/etc/group-') do
      it { should exist }
      it { should be_readable.by 'owner' }
      it { should be_writable.by 'owner' }
      it { should_not be_executable.by 'owner' }
      it { should be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
      its(:uid) { should cmp 0 }
      its(:gid) { should cmp 0 }
      its(:sticky) { should equal false }
      its(:suid) { should equal false }
      its(:sgid) { should equal false }
    end
  end

  control 'cis-dil-benchmark-6.1.9' do
    title 'Ensure permissions on /etc/gshadow- are configured'
    desc "The /etc/gshadow- file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.\n\nRationale: It is critical to ensure that the /etc/gshadow- file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions."
    impact 1.0

    tag cis: 'distribution-independent-linux:6.1.9'
    tag level: 1

    describe file('/etc/gshadow-') do
      it { should exist }
      it { should_not be_readable.by 'owner' }
      it { should_not be_writable.by 'owner' }
      it { should_not be_executable.by 'owner' }
      it { should_not be_readable.by 'group' }
      it { should_not be_writable.by 'group' }
      it { should_not be_executable.by 'group' }
      it { should_not be_readable.by 'other' }
      it { should_not be_writable.by 'other' }
      it { should_not be_executable.by 'other' }
      its(:uid) { should cmp 0 }
      its(:gid) { should cmp 0 }
      its(:sticky) { should equal false }
      its(:suid) { should equal false }
      its(:sgid) { should equal false }
    end
  end
end
