project('bandaid', 'c')
systemd = dependency('libsystemd')
seccomp = dependency('libseccomp')
executable('bandaid', 'bandaid.c', install : true, dependencies : [systemd, seccomp])
