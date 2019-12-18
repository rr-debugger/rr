/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include <linux/joystick.h>

int main(void) {
    int fd = open("/dev/input/js0", O_RDONLY);
    if (fd < 0) {
        atomic_puts("Can't open joystick device, aborting test");
        atomic_puts("EXIT-SUCCESS");
        return 0;
    }

    int ret = 0;

    // JSIOCGVERSION
    uint32_t *version;
    ALLOCATE_GUARD(version, 'a');
    test_assert(0 == ioctl(fd, JSIOCGVERSION, version));
    VERIFY_GUARD(version);

    // JSIOCGAXES
    uint8_t *number_of_axes;
    ALLOCATE_GUARD(number_of_axes, 'b');
    test_assert(0 == ioctl(fd, JSIOCGAXES, number_of_axes));
    VERIFY_GUARD(number_of_axes);

    // JSIOCGBUTTONS
    uint8_t *number_of_buttons;
    ALLOCATE_GUARD(number_of_buttons, 'c');
    test_assert(0 == ioctl(fd, JSIOCGBUTTONS, number_of_buttons));
    VERIFY_GUARD(number_of_buttons);

    // This is not supported for now, since the size of the data returned
    // depends on the number of axes, which can only be determined by querying
    // the device.
#if 0
    // JSIOCGCORR
    struct js_corr **corr;
    size_t corr_size = *number_of_axes * sizeof(struct js_corr);
    corr = allocate_guard(corr_size, 'd');
    test_assert(0 == ioctl(fd, JSIOCGCORR, corr));
    verify_guard(corr_size, corr);
#endif

    // JSIOCGAXMAP
    uint8_t (*axis_mapping)[ABS_CNT];
    ALLOCATE_GUARD(axis_mapping, 'e');
    ret = ioctl(fd, JSIOCGAXMAP, axis_mapping);
    test_assert(ret > 0 && (unsigned)ret <= sizeof(*axis_mapping));
    VERIFY_GUARD(axis_mapping);

    // JSIOCGBTNMAP
    uint16_t (*button_mapping)[KEY_MAX - BTN_MISC + 1];
    ALLOCATE_GUARD(button_mapping, 'f');
    ret = ioctl(fd, JSIOCGBTNMAP, button_mapping);
    test_assert(ret > 0 && (unsigned)ret <= sizeof(*button_mapping));
    VERIFY_GUARD(button_mapping);

    // JSIOCGNAME
    // With zero size, this should always succeed
    test_assert(0 == ioctl(fd, JSIOCGNAME(0), NULL));

    uint8_t (*name)[1024];
    ALLOCATE_GUARD(name, 'g');
    ret = ioctl(fd, JSIOCGNAME(sizeof(*name)), *name);
    test_assert((ret == -1 && errno == EFAULT) ||
                (ret >= 0 && (unsigned)ret <= sizeof(*name)));
    VERIFY_GUARD(name);

    atomic_puts("EXIT-SUCCESS");
    return 0;
}
