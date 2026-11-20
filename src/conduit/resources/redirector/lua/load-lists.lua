local function load_file_into_dict(path, dict_name)
    local dict = ngx.shared[dict_name]
    assert(dict, "shared dict not declared in nginx.conf: " .. dict_name)

    local f, err = io.open(path, "r")
    if not f then
        error(("cannot open %s: %s"):format(path, err or "unknown"))
    end

    local count = 0
    for line in f:lines() do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^#") then
            local ok, cache_err = dict:set(trimmed, true)
            if not ok then
                error(("dict %s set failed for %q: %s"):format(dict_name, trimmed, cache_err or "unknown"))
            end
            count = count + 1
        end
    end
    f:close()

    ngx.log(ngx.NOTICE, ("loaded %d entries from %s into %s"):format(count, path, dict_name))
end

local function load_kv_into_dict(path, dict_name)
    local dict = ngx.shared[dict_name]
    assert(dict, "shared dict not declared in nginx.conf: " .. dict_name)

    local f, err = io.open(path, "r")
    if not f then
        error(("cannot open %s: %s"):format(path, err or "unknown"))
    end

    local count = 0
    for line in f:lines() do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and not trimmed:match("^#") then
            local colon = trimmed:find(":", 1, true)
            if colon then
                local key = trimmed:sub(1, colon - 1)
                local val = trimmed:sub(colon + 1)
                local ok, cache_err = dict:set(key, val)
                if not ok then
                    error(("dict %s set failed for %q: %s"):format(dict_name, key, cache_err or "unknown"))
                end
                count = count + 1
            end
        end
    end
    f:close()

    ngx.log(ngx.NOTICE, ("loaded %d entries from %s into %s"):format(count, path, dict_name))
end

load_file_into_dict("/etc/openresty/data/sni-allow.txt", "allow_sni")
load_file_into_dict("/etc/openresty/data/uri-allow.txt", "allow_uri")
load_file_into_dict("/etc/openresty/data/ua-allow.txt",  "allow_ua")
load_file_into_dict("/etc/openresty/data/ja3-allow.txt", "allow_ja3")
load_kv_into_dict("/etc/openresty/data/headers-require.txt", "require_headers")

ngx.log(ngx.NOTICE, "redirector allowlists loaded")
