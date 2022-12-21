all: fxs
.PHONY: all

# Include standard NCS examples build definitions and rules
include $(NCS_DIR)/src/ncs/build/include.ncs.mk

SRC = $(wildcard yang/*.yang)
DIRS = ../load-dir java/src/$(JDIR)/$(NS)
FXS = $(SRC:yang/%.yang=../load-dir/%.fxs)

## Uncomment and patch the line below if you have a dependency to a NED
## or to other YANG files
YANGPATH += /home/pod0/ncs-run/packages/cisco-asa-cli-6.16/src/ncsc-out/modules/yang
YANGPATH += /home/pod0/ncs-run/packages/cisco-ios-cli-6.88/src/ncsc-out/modules/yang
YANGPATH += /home/pod0/ncs-run/packages/cisco-staros-cli-5.47/src/ncsc-out/modules/yang

YANGPATH += /home/pod0/ncs-run/packages/cisco-asa-cli-6.16/src
YANGPATH += /home/pod0/ncs-run/packages/cisco-ios-cli-6.88/src
YANGPATH += /home/pod0/ncs-run/packages/cisco-staros-cli-5.47/src


NCSCPATH   = $(YANGPATH:%=--yangpath %)
YANGERPATH = $(YANGPATH:%=--path %)

fxs: $(DIRS) $(FXS)

$(DIRS):
	mkdir -p $@

../load-dir/%.fxs: yang/%.yang
	$(NCSC)  `ls $*-ann.yang  > /dev/null 2>&1 && echo "-a $*-ann.yang"` \
             $(NCSCPATH) -c -o $@ $<

clean:
	rm -rf $(DIRS)
.PHONY: clean
