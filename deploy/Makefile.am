EXTRA_DIST = app-content-match.csv app-host-match.csv \
             clearos exec-pre.sh netifyd.conf netifyd.service netifyd.tmpf

all: app-content-match.csv app-host-match.csv

app-content-match.csv: ../util/nd-match-export
	../util/nd-match-export -C app-content-match.csv

app-host-match.csv: ../util/nd-match-export
	../util/nd-match-export -H .app-host-match.csv
	egrep -v '^.*,163$$' .app-host-match.csv > app-host-match.csv

