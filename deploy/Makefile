all: content-match.csv host-protocol.csv

content-match.csv: ../util/nd-content-match-export
	../util/nd-content-match-export -C content-match.csv

host-protocol.csv: ../util/nd-content-match-export
	../util/nd-content-match-export -H host-protocol.csv
	sed -i -f host-protocol.sed host-protocol.csv

