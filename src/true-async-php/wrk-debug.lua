wrk.method = "GET"

response_errors = {}

function response(status, headers, body)
    if status ~= 200 then
        local key = status .. ": " .. body:sub(1, 100)
        response_errors[key] = (response_errors[key] or 0) + 1
    end
end

function done(summary, latency, requests)
    print("\n=== Non-2xx Responses ===")
    for error, count in pairs(response_errors) do
        print(string.format("%d times: %s", count, error))
    end
end
