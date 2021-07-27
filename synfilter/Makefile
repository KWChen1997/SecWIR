SUBDIRS		= syndrv filter

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for d in $(SUBDIRS); do\
		$(MAKE) -C $$d clean;\
	done

.PHONY: $(SUBDIRS)
