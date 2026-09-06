FROM ubuntu:24.04
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    build-essential pkg-config libsecret-1-dev libglib2.0-dev libpolkit-gobject-1-dev \
    libjson-glib-dev libssl-dev python3 e2fsprogs ca-certificates gnome-keyring dbus-daemon \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /source
CMD ["make", "BUILD=/tmp/ea-build", "check", "check-install", "check-secret-service"]
