# Netify Agent JSON Socket Example "jq" Filter

# Filter by "flow" JSON objects
def flow_select(j):
    if has("type") then
        j
    else
        empty
    end | if .["type"] == "flow" then
        j
    else
        empty
    end;

# Map the following fields into an array
def flow_print:
    .["flow"] |
        [
            .["last_seen_at"],
            .["digest"],
            .["local_ip"],
            .["local_port"],
            .["other_ip"],
            .["other_port"],
            .["detected_protocol_name"],
            .["detected_application_name"]
        ] |
        map(tostring);

# Delimit the resulting array fields with one space
flow_select(.) | flow_print | join(" ")
