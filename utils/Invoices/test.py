import base64

def parse_tlv(data: bytes):
    pos = 0
    tlv = {}
    while pos < len(data):
        tag = data[pos]
        length = data[pos+1]
        value = data[pos+2:pos+2+length]
        try:
            # Try decoding as UTF-8, fallback to Base64
            tlv[tag] = value.decode('utf-8')
        except UnicodeDecodeError:
            tlv[tag] = base64.b64encode(value).decode('utf-8')
        pos += 2 + length
    return tlv

# Base64 QR string from your XML
qr_base64 = "AQhNeSBTdG9yZQIPMzEwMDAwMDAwMDAwMDkzAxQyMDI1LTA4LTE4VDIyOjQ1OjIyWgQGMjg3LjUwBQUzNy41MAYsNUp1d08zSkNmR0JYS2R6Y3k1eTJRYWVvaGI1b0xtUURZOU5YMy9kSVl5UT0HYE1FWUNJUUM5N3dlYzlaZEZ6SmFham5Ia21JalRSNzVIZ1hvQkhlWjVXeG9teDlrcVZRSWhBTmRXNW85K2ZTb0VOWm8rdEZqZitQZENMZFZWMWV2S0srR3pTbUhkWU94WQhBBKFgimtEmvRSBK0zr9LgJAtVSCl8VPZz6cdr5X+MoTHo8vHNNlyW5Q6u7T8naPJqtGoTjJjaPIMJ4u17dSk/VHgJRzBFAiEAsT+JyGadZcJQpRtxrfJyLyirBou8V0dWNCu94j26oBsCID2ELgzyOAwEAM9LOZ3a6I8kDqApHcsTTdTvl6psL+tc"
qr_bytes = base64.b64decode(qr_base64)

decoded_qr = parse_tlv(qr_bytes)
for k, v in decoded_qr.items():
    print(f"Tag {k}: {v}")
