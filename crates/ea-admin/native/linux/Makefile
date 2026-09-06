CC ?= cc
PKGS = gio-2.0 libsecret-1 polkit-gobject-1 json-glib-1.0 openssl
CPPFLAGS += -D_GNU_SOURCE -I. $(shell pkg-config --cflags $(PKGS))
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong -fPIE
LDLIBS += $(shell pkg-config --libs $(PKGS))
LDFLAGS += -pie -Wl,-z,relro,-z,now
BUILD ?= build
SOURCES = main.c protocol.c transport.c crypto.c account.c marker.c provider.c watch.c watch_events.c

.PHONY: all check check-maintenance check-install check-secret-service clean
all: $(BUILD)/ea-native-operator
$(BUILD):
	mkdir -p $@
$(BUILD)/ea-native-operator: $(SOURCES) ea_native.h watch.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SOURCES) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test-core: tests/test_core.c protocol.c crypto.c ea_native.h watch.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_core.c protocol.c crypto.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test-watch: tests/test_watch.c $(filter-out main.c,$(SOURCES)) watch.h ea_native.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_watch.c $(filter-out main.c watch.c,$(SOURCES)) $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test-marker: tests/test_marker.c marker.c crypto.c protocol.c ea_native.h watch.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_marker.c marker.c crypto.c protocol.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test-maintenance: tests/test_maintenance.c marker.c crypto.c protocol.c ea_native.h watch.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_maintenance.c marker.c crypto.c protocol.c $(LDFLAGS) $(LDLIBS) -o $@
$(BUILD)/test-secret-service: tests/test_secret_service.c provider.c marker.c account.c crypto.c protocol.c watch_events.c transport.c watch.h ea_native.h | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/test_secret_service.c marker.c account.c crypto.c protocol.c watch_events.c transport.c $(LDFLAGS) $(LDLIBS) -o $@
check: all $(BUILD)/test-core $(BUILD)/test-watch check-maintenance
	$(BUILD)/test-core
	$(BUILD)/test-watch
	python3 -B tests/test_watch_process.py $(BUILD)/test-watch
	python3 tests/test_ipc.py $(BUILD)/ea-native-operator
check-maintenance: $(BUILD)/test-maintenance
	$(BUILD)/test-maintenance
	python3 -B tests/test_restore.py
check-install: all $(BUILD)/test-marker
	python3 tests/test_install.py $(BUILD)
check-secret-service: $(BUILD)/test-secret-service
	python3 tests/run_secret_service.py $(BUILD)/test-secret-service
clean:
	rm -rf -- $(BUILD)
