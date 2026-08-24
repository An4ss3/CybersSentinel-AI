@load base/protocols/conn
@load base/protocols/http
@load policy/protocols/http/header-names

redef tcp_content_deliver_all_orig = T;
redef tcp_content_deliver_all_resp = T;
redef udp_content_deliver_all_orig = T;
redef udp_content_deliver_all_resp = T;

module ContentFeature;

export {
    redef enum Log::ID += { LOG };

    option partition: string = "UNSET";
    option pseudonym_salt: string = "UNSET";
    option prefix_bytes: count = 64;
    option stop_after: interval = 0secs;

    type Info: record {
        window_key: string &log;
        source_payload_entropy_normalized: double &log &optional;
        destination_payload_entropy_normalized: double &log &optional;
        source_non_printable_ratio: double &log &optional;
        destination_non_printable_ratio: double &log &optional;
        payload_prefix_repeat_ratio: double &log &optional;
        normalized_header_template_repeat_ratio: double &log &optional;
        source_entropy_flows: count &log;
        destination_entropy_flows: count &log;
        source_payload_bytes: count &log;
        destination_payload_bytes: count &log;
        source_prefixes: count &log;
        header_templates: count &log;
    };
}

redef record connection += {
    cf_orig_entropy: opaque of entropy &optional;
    cf_resp_entropy: opaque of entropy &optional;
    cf_orig_bytes: count &default=0;
    cf_resp_bytes: count &default=0;
    cf_orig_non_printable: count &default=0;
    cf_resp_non_printable: count &default=0;
    cf_orig_prefix: string &default="";
    cf_http_method_class: string &optional;
    cf_http_version_class: string &optional;
};

global seen_windows: set[string];
global source_entropy_sum: table[string] of double &default=0.0;
global destination_entropy_sum: table[string] of double &default=0.0;
global source_entropy_flows: table[string] of count &default=0;
global destination_entropy_flows: table[string] of count &default=0;
global source_payload_bytes: table[string] of count &default=0;
global destination_payload_bytes: table[string] of count &default=0;
global source_non_printable: table[string] of count &default=0;
global destination_non_printable: table[string] of count &default=0;
global source_prefix_count: table[string] of count &default=0;
global header_template_count: table[string] of count &default=0;
global source_prefix_hashes: table[string] of set[string];
global header_template_hashes: table[string] of set[string];

global allowed_methods: set[string] = set(
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
);
global allowed_versions: set[string] = set("1.0", "1.1", "2", "2.0", "3");

function normalized_method(method: string): string
    {
    local upper = to_upper(method);
    return upper in allowed_methods ? upper : "OTHER";
    }

function normalized_version(version: string): string
    {
    return version in allowed_versions ? version : "OTHER";
    }

function service_of(c: connection): string
    {
    if ( ! c?$service || |c$service| == 0 )
        return "none";
    if ( |c$service| != 1 )
        return "__unsupported_cardinality__";
    for ( service in c$service )
        return to_lower(service);
    return "none";
    }

function canonical_window_key(c: connection, service: string): string
    {
    local transport = fmt("%s", get_port_transport_proto(c$id$resp_p));
    local bucket = double_to_count(
        floor(time_to_double(c$start_time) / 60.0) * 60.0
    );
    return fmt("%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%d",
               partition, c$id$orig_h, c$id$resp_h, transport, service, bucket);
    }

function observe_content(c: connection, is_orig: bool, contents: string)
    {
    if ( |contents| == 0 )
        return;

    # gsub is implemented in the Zeek runtime. It removes printable ASCII plus
    # TAB/CR/LF, leaving exactly the non-printable bytes to count.
    local non_printable = |gsub(contents, /[\x09\x0a\x0d\x20-\x7e]/, "")|;

    if ( is_orig )
        {
        if ( ! c?$cf_orig_entropy )
            c$cf_orig_entropy = entropy_test_init();
        entropy_test_add(c$cf_orig_entropy, contents);
        c$cf_orig_bytes += |contents|;
        c$cf_orig_non_printable += non_printable;

        if ( |c$cf_orig_prefix| < prefix_bytes )
            {
            local remaining = prefix_bytes - |c$cf_orig_prefix|;
            local take = |contents| < remaining ? |contents| : remaining;
            c$cf_orig_prefix = cat(c$cf_orig_prefix, sub_bytes(contents, 0, take));
            }
        }
    else
        {
        if ( ! c?$cf_resp_entropy )
            c$cf_resp_entropy = entropy_test_init();
        entropy_test_add(c$cf_resp_entropy, contents);
        c$cf_resp_bytes += |contents|;
        c$cf_resp_non_printable += non_printable;
        }
    }

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string)
    {
    observe_content(c, is_orig, contents);
    }

event udp_contents(c: connection, is_orig: bool, contents: string)
    {
    observe_content(c, is_orig, contents);
    }

function normalized_entropy(handle: opaque of entropy, bytes: count): double
    {
    local result = entropy_test_finish(handle);
    local alphabet = bytes < 256 ? bytes : 256;
    if ( alphabet < 2 )
        return -1.0;
    local maximum = ln(count_to_double(alphabet)) / ln(2.0);
    return result$entropy / maximum;
    }

event connection_state_remove(c: connection)
    {
    local service = service_of(c);
    if ( service == "__unsupported_cardinality__" )
        return;
    local key = canonical_window_key(c, service);

    if ( c$cf_orig_bytes > 0 )
        {
        add seen_windows[key];
        source_payload_bytes[key] += c$cf_orig_bytes;
        source_non_printable[key] += c$cf_orig_non_printable;
        if ( c?$cf_orig_entropy && c$cf_orig_bytes >= 2 )
            {
            local source_value = normalized_entropy(c$cf_orig_entropy, c$cf_orig_bytes);
            if ( source_value >= 0.0 )
                {
                source_entropy_sum[key] += source_value;
                source_entropy_flows[key] += 1;
                }
            }
        if ( |c$cf_orig_prefix| > 0 )
            {
            if ( key !in source_prefix_hashes )
                source_prefix_hashes[key] = set();
            add source_prefix_hashes[key][sha256_hash(c$cf_orig_prefix)];
            source_prefix_count[key] += 1;
            }
        }

    if ( c$cf_resp_bytes > 0 )
        {
        add seen_windows[key];
        destination_payload_bytes[key] += c$cf_resp_bytes;
        destination_non_printable[key] += c$cf_resp_non_printable;
        if ( c?$cf_resp_entropy && c$cf_resp_bytes >= 2 )
            {
            local destination_value = normalized_entropy(c$cf_resp_entropy, c$cf_resp_bytes);
            if ( destination_value >= 0.0 )
                {
                destination_entropy_sum[key] += destination_value;
                destination_entropy_flows[key] += 1;
                }
            }
        }
    }

# The URI arguments are required by the Zeek event signature but are never read
# or copied. Only bounded method/version classes survive until request headers.
event http_request(c: connection, method: string, original_uri: string,
                   unescaped_uri: string, version: string) &priority=-5
    {
    c$cf_http_method_class = normalized_method(method);
    c$cf_http_version_class = normalized_version(version);
    }

# Header values, URI, host, cookies and identifiers are never copied. The
# transient template contains only a bounded method class, version class and the
# ordered upper-case header names. Only its SHA-256 enters window state.
event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list) &priority=-5
    {
    if ( ! is_orig || ! c?$cf_http_method_class || ! c?$cf_http_version_class )
        return;

    local template = fmt("%s|%s",
                         c$cf_http_method_class,
                         c$cf_http_version_class);
    for ( index in hlist )
        template = cat(template, "|", to_upper(hlist[index]$name));

    # Consume exactly once: nested MIME headers are not request templates.
    delete c$cf_http_method_class;
    delete c$cf_http_version_class;

    local key = canonical_window_key(c, "http");
    add seen_windows[key];
    if ( key !in header_template_hashes )
        header_template_hashes[key] = set();
    add header_template_hashes[key][sha256_hash(template)];
    header_template_count[key] += 1;
    }

event zeek_init() &priority=-100
    {
    if ( partition == "UNSET" || pseudonym_salt == "UNSET" )
        terminate();

    Log::create_stream(LOG, [$columns=Info, $path="content_features"]);
    local streams_to_disable: set[Log::ID] = set();
    for ( stream_id in Log::active_streams )
        if ( stream_id != LOG )
            add streams_to_disable[stream_id];
    for ( stream_id in streams_to_disable )
        Log::disable_stream(stream_id);
    }

event bounded_stop()
    {
    terminate();
    }

event network_time_init()
    {
    if ( stop_after > 0secs )
        schedule stop_after { bounded_stop() };
    }

event zeek_done()
    {
    for ( key in seen_windows )
        {
        local info: Info = [
            $window_key=sha256_hash(pseudonym_salt, key),
            $source_entropy_flows=source_entropy_flows[key],
            $destination_entropy_flows=destination_entropy_flows[key],
            $source_payload_bytes=source_payload_bytes[key],
            $destination_payload_bytes=destination_payload_bytes[key],
            $source_prefixes=source_prefix_count[key],
            $header_templates=header_template_count[key]
        ];

        if ( source_entropy_flows[key] > 0 )
            info$source_payload_entropy_normalized =
                source_entropy_sum[key] / count_to_double(source_entropy_flows[key]);
        if ( destination_entropy_flows[key] > 0 )
            info$destination_payload_entropy_normalized =
                destination_entropy_sum[key] / count_to_double(destination_entropy_flows[key]);
        if ( source_payload_bytes[key] > 0 )
            info$source_non_printable_ratio =
                count_to_double(source_non_printable[key]) /
                count_to_double(source_payload_bytes[key]);
        if ( destination_payload_bytes[key] > 0 )
            info$destination_non_printable_ratio =
                count_to_double(destination_non_printable[key]) /
                count_to_double(destination_payload_bytes[key]);
        if ( source_prefix_count[key] > 0 )
            info$payload_prefix_repeat_ratio =
                1.0 - count_to_double(|source_prefix_hashes[key]|) /
                      count_to_double(source_prefix_count[key]);
        if ( header_template_count[key] > 0 )
            info$normalized_header_template_repeat_ratio =
                1.0 - count_to_double(|header_template_hashes[key]|) /
                      count_to_double(header_template_count[key]);

        Log::write(LOG, info);
        }
    }
