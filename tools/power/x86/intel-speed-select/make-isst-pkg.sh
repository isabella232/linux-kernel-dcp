#!/usr/bin/bash -e

# usage: <script> <kernel dir> <version string>
SELF="make-isst-pkg.sh"
KERNEL_DIR=$1
VERSION=$2

usage() {
	echo "Usage:"
	echo "  ${SELF} KERNEL_SRC_DIR VERSION_NUMBER"
	echo "    KERNEL_SRC_DIR must point to kernel source root directory"
	echo "    VERSION_NUMBER is an arbitrary string (e.g. v1.4)"
	exit 1
}

# check parameters
if [ "$KERNEL_DIR" = "" ]; then
	echo "Please specify kernel source directory"
	usage
fi

# we have to be inside kernel tree
if [ ! -f $KERNEL_DIR/include/uapi/linux/isst_if.h ]; then
	echo "$KERNEL_DIR is not a valid kernel source code directory"
	usage
fi

if [ "${2}" == ""]; then
if [ "$version" = "" ]; then
	echo "Please specify version string"
	usage
else
	VERSION=$version
fi
fi

# locate isst dir
ISST_DIR=$KERNEL_DIR/tools/power/x86/intel-speed-select
PKGNAME="intel-speed-select-${VERSION}"

echo $ISST_DIR
echo $PKGNAME

# create temporary directory
TMPDIR=$(mktemp -d)

# copy headers to isst dir
make -C $ISST_DIR prepare

# copy source code
cp $ISST_DIR/*.c $TMPDIR
cp $ISST_DIR/*.h $TMPDIR
cp -r $ISST_DIR/include $TMPDIR

# create custom Makefile
cat > $TMPDIR/Makefile << EOF
all:
	gcc *.c -D_GNU_SOURCE -I include -I/usr/include/libnl3 -o intel-speed-select -lnl-genl-3 -lnl-3
clean:
	rm intel-speed-select
install:
	cp intel-speed-select /usr/local/bin
uninstall:
	rm /usr/local/bin/intel-speed-select
EOF

# create a tarball with self-contained package
tar --transform="s|${TMPDIR}|${PKGNAME}|" -czvhPf $PKGNAME.tar.gz $TMPDIR/*

# cleanup
rm -rf $TMPDIR
