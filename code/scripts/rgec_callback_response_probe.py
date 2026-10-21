"""Native location-specific warning policies and response-state continuations."""
import sys

sys.path.insert(0, '/')
import rgec_residual_probe as residual


def function(name):
    return ('int ' + name + '(int x) { volatile char a[4096]; '
            'a[0] = x; return a[0]; }\n').encode()


def policy(level):
    return ('#pragma clang diagnostic ' + level + ' "-Wframe-larger-than="\n').encode()


def variants():
    begin = b'\n#pragma clang diagnostic push\n'
    end = b'#pragma clang diagnostic pop\n'
    return {
        'ast-pragma-ignored': begin + policy('ignored') + function('rgec_ignored_stack') + end,
        'ast-pragma-error': begin + policy('error') + function('rgec_error_stack') + end,
        'ast-mixed-policy': begin + policy('ignored') + function('rgec_mixed_ignored') +
            policy('error') + function('rgec_mixed_error') + policy('warning') +
            function('rgec_mixed_warning') + end,
        'ast-error-limit': begin + policy('error') + b''.join(
            function('rgec_limit_stack_' + str(i)) for i in range(5)) + end,
        'ast-error-after-ignored': begin + policy('ignored') + function('rgec_first_ignored') +
            policy('error') + function('rgec_second_error') + policy('ignored') +
            function('rgec_last_ignored') + end,
    }


if __name__ == '__main__':
    residual.variants = variants
    residual.main(sys.argv[1])
