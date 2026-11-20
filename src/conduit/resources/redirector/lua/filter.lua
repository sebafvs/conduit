local DECOY = "__DECOY_URL__"

local function reject(tag)
    ngx.var.redir_reject = tag
    return ngx.redirect(DECOY, ngx.HTTP_MOVED_TEMPORARILY)
end

local function safe_get(dict, key)
    local ok, val = pcall(function() return dict:get(key) end)
    if not ok then return nil end
    return val
end

local h = ngx.req.get_headers()

local ua = h["User-Agent"] or ""
if not safe_get(ngx.shared.allow_ua, ua) then
    return reject("bad-ua")
end

local rh = ngx.shared.require_headers
local rh_keys = rh:get_keys(64)
for _, hdr_name in ipairs(rh_keys) do
    local check_val = rh:get(hdr_name)
    local actual = h[hdr_name] or ""
    if check_val == "present" then
        if actual == "" then
            return reject("missing-" .. hdr_name)
        end
    else
        if actual ~= check_val then
            return reject("bad-challenge")
        end
    end
end

local uri = ngx.var.uri or ""
local matched = false
local candidate = uri
while candidate ~= "" do
    if safe_get(ngx.shared.allow_uri, candidate) then
        matched = true
        break
    end
    local parent = candidate:match("^(.-)/[^/]+$")
    candidate = parent or ""
end
if not matched then
    return reject("bad-uri")
end

local ja3 = ngx.var.http_ssl_ja3_hash
if ja3 and ja3 ~= "" then
    if not safe_get(ngx.shared.allow_ja3, ja3) then
        return reject("bad-ja3")
    end
end
