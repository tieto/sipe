SMILEYS = \
	00.png \
	01.gif \
	02.gif \
	03.gif \
	04.gif \
	05.gif \
	06.gif \
	07.gif \
	08.gif \
	09.gif \
	10.gif \
	11.gif \
	12.gif \
	14.gif \
	15.gif \
	16.gif \
	17.gif \
	18.gif \
	19.gif \
	20.gif \
	21.gif \
	22.gif \
	23.gif \
	24.gif \
	25.gif \
	26.gif \
	27.gif \
	28.gif \
	29.gif \
	32.gif \
	33.gif \
	34.gif \
	35.gif \
	36.gif \
	37.gif \
	38.gif \
	39.gif \
	40.gif \
	41.gif \
	42.gif \
	43.gif \
	44.gif \
	45.gif \
	46.gif \
	47.gif \
	48.gif \
	49.gif \
	50.gif \
	52.gif \
	53.gif \
	57.gif \
	58.gif \
	59.gif \
	62.gif \
	63.gif \
	64.gif \
	65.gif \
	66.gif \
	67.gif \
	68.gif \
	69.gif \
	70.gif \
	71.gif \
	72.gif \
	73.gif \
	74.gif \
	75.gif \
	76.gif \
	77.gif \
	78.gif \
	79.gif \
	80.gif 

pidginsmileypix_in_files = sipe.theme.in

pidginsmileypixdir = $(datadir)/pixmaps/pidgin/emotes/sipe
pidginsmileypix_DATA = \
        $(SMILEYS) \
        theme

theme: sipe.theme.in
	sed -e 's/^_Name=/Name=/' \
	    -e 's/^_Description=/Description=/' \
	    -e 's/^_Author=/Author=/' \
	$< > $@

EXTRA_DIST = $(SMILEYS) $(pidginsmileypix_in_files) theme
	

