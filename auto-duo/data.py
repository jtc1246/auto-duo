from myBasics import base64ToStr  # pip install myBasics
import hashlib


def hash_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


base64_data = '''
Y29uc3QgY3J5cHRvID0gcmVxdWlyZSgiY3J5cHRvIik7CmNvbnN0IFhNTEh0dHBSZXF1ZXN0ID0gcmVx
dWlyZSgiQGFlbGZxdWVlbi94bWxodHRwcmVxdWVzdCIpLlhNTEh0dHBSZXF1ZXN0OyAvLyBucG0gaW5z
dGFsbCBAYWVsZnF1ZWVuL3htbGh0dHByZXF1ZXN0Ci8vIGNhbid0IHVzZSB4bWxodHRwcmVxdWVzdCBk
aXJlY3RseSwgc2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9kcml2ZXJkYW4vbm9kZS1YTUxIdHRwUmVxdWVz
dC9wdWxsLzE2OQovLyBzZXRSZXF1ZXN0SGVhZGVyIGRvZXMgbm90IHdvcmsgaW4gdGhhdC4KCgpjb25z
dCBUQVNLID0gIiQwMSQiOyAvLyBbQV1jdGl2YXRlIG9yIFtDXWhlY2sKY29uc3QgUVJfQ09ERSA9ICIk
MDIkIjsgLy8gb25seSB2YWxpZCB3aGVuIFRBU0sgaXMgQWN0aXZhdGUKY29uc3QgQkFTRTY0X0RJQ1Qg
PSAiJDAzJCI7IC8vIG9ubHkgdmFsaWQgd2hlbiBUQVNLIGlzIENoZWNrCgoKY29uc3QgTVlfUFJJTlRf
U0lHTkFMID0gIiRqdGMtYXV0by1kdW8tanMtb3V0cHV0LWh2OWc4eXZxdW5xY251b3d5YmdvYmh1d3Ik
anRjJCI7CgpmdW5jdGlvbiBwcmludChzdHIpewogIGNvbnNvbGUubG9nKE1ZX1BSSU5UX1NJR05BTCAr
IHN0ciArIE1ZX1BSSU5UX1NJR05BTCk7Cn0KCmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9CYXNlNjQoYnVm
ZmVyKSB7CiAgbGV0IGJpbmFyeSA9ICIiOwogIGxldCBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJ1ZmZl
cik7CiAgbGV0IGxlbiA9IGJ5dGVzLmJ5dGVMZW5ndGg7CiAgZm9yIChsZXQgaSA9IDA7IGkgPCBsZW47
IGkrKykgewogICAgYmluYXJ5ICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZXNbaV0pOwogIH0KICBy
ZXR1cm4gYnRvYShiaW5hcnkpOwp9CgpmdW5jdGlvbiB0d29EaWdpdHMoaW5wdXQpIHsKICByZXR1cm4g
aW5wdXQudG9TdHJpbmcoKS5wYWRTdGFydCgyLCAnMCcpOwp9CgpmdW5jdGlvbiBiYXNlNjRUb0FycmF5
QnVmZmVyKGJhc2U2NCkgewogIHZhciBiaW5hcnlfc3RyaW5nID0gYXRvYihiYXNlNjQpOwogIHZhciBs
ZW4gPSBiaW5hcnlfc3RyaW5nLmxlbmd0aDsKICB2YXIgYnl0ZXMgPSBuZXcgVWludDhBcnJheShsZW4p
OwogIGZvciAodmFyIGkgPSAwOyBpIDwgbGVuOyBpKyspIHsKICAgICAgYnl0ZXNbaV0gPSBiaW5hcnlf
c3RyaW5nLmNoYXJDb2RlQXQoaSk7CiAgfQogIHJldHVybiBieXRlcy5idWZmZXI7Cn0KCnZhciBkaSA9
IHt9OwoKLy8g55So5LqO6YCa6L+H5LqM57u056CB6I635Y+W5a+G6ZKlCmFzeW5jIGZ1bmN0aW9uIGFj
dGl2YXRlRGV2aWNlKHJhd0NvZGUpIHsKICAvLyBTcGxpdCBhY3RpdmF0aW9uIGNvZGUgaW50byBpdHMg
dHdvIGNvbXBvbmVudHM6IGlkZW50aWZpZXIgYW5kIGhvc3QuCiAgbGV0IGNvZGUgPSByYXdDb2RlLnNw
bGl0KCctJyk7CiAgLy8gRGVjb2RlIEJhc2U2NCB0byBnZXQgaG9zdAogIGxldCBob3N0ID0gYXRvYihj
b2RlWzFdKTsKICBsZXQgaWRlbnRpZmllciA9IGNvZGVbMF07CiAgLy8gRW5zdXJlIHRoaXMgY29kZSBp
cyBjb3JyZWN0IGJ5IGNvdW50aW5nIHRoZSBjaGFyYWN0ZXJzCiAgaWYoY29kZVswXS5sZW5ndGggIT0g
MjAgfHwgY29kZVsxXS5sZW5ndGggIT0gMzgpIHsKICAgIHRocm93ICJJbGxlZ2FsIG51bWJlciBvZiBj
aGFyYWN0ZXJzIGluIGFjdGl2YXRpb24gY29kZSI7CiAgfQoKICBsZXQgdXJsID0gJ2h0dHBzOi8vJyAr
IGhvc3QgKyAnL3B1c2gvdjIvYWN0aXZhdGlvbi8nICsgaWRlbnRpZmllcjsKICAvLyBDcmVhdGUgbmV3
IHBhaXIgb2YgUlNBIGtleXMKICBsZXQga2V5UGFpciA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZ2VuZXJh
dGVLZXkoewogICAgbmFtZTogIlJTQVNTQS1QS0NTMS12MV81IiwKICAgIG1vZHVsdXNMZW5ndGg6IDIw
NDgsCiAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzB4MDEsIDB4MDAsIDB4MDFdKSwK
ICAgIGhhc2g6ICJTSEEtNTEyIgogIH0sIHRydWUsIFsic2lnbiIsICJ2ZXJpZnkiXSk7CgogIC8vIENv
bnZlcnQgcHVibGljIGtleSB0byBQRU0gZm9ybWF0IHRvIHNlbmQgdG8gRHVvCiAgbGV0IHBlbUZvcm1h
dCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCJzcGtpIiwga2V5UGFpci5wdWJsaWNLZXkp
OwogIHBlbUZvcm1hdCA9IGJ0b2EoU3RyaW5nLmZyb21DaGFyQ29kZSguLi5uZXcgVWludDhBcnJheShw
ZW1Gb3JtYXQpKSkubWF0Y2goLy57MSw2NH0vZykuam9pbignXG4nKTsKICBwZW1Gb3JtYXQgPSBgLS0t
LS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbiR7cGVtRm9ybWF0fVxuLS0tLS1FTkQgUFVCTElDIEtFWS0t
LS0tYDsKCiAgLy8gRXhwb3J0aW5nIGtleXMgcmV0dXJucyBhbiBhcnJheSBidWZmZXIuIENvbnZlcnQg
aXQgdG8gQmFzZTY0IHN0cmluZyBmb3Igc3RvcmluZwogIGxldCBwdWJsaWNSYXcgPSBhcnJheUJ1ZmZl
clRvQmFzZTY0KGF3YWl0IGNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KCJzcGtpIiwga2V5UGFpci5wdWJs
aWNLZXkpKTsKICBsZXQgcHJpdmF0ZVJhdyA9IGFycmF5QnVmZmVyVG9CYXNlNjQoYXdhaXQgY3J5cHRv
LnN1YnRsZS5leHBvcnRLZXkoInBrY3M4Iiwga2V5UGFpci5wcml2YXRlS2V5KSk7CgogIC8vIEluaXRp
YWxpemUgbmV3IEhUVFAgcmVxdWVzdAogIGxldCByZXF1ZXN0ID0gbmV3IFhNTEh0dHBSZXF1ZXN0KCk7
CiAgbGV0IGVycm9yID0gZmFsc2U7CiAgcmVxdWVzdC5vcGVuKCdQT1NUJywgdXJsLCB0cnVlKTsKICBy
ZXF1ZXN0LnNldFJlcXVlc3RIZWFkZXIoIkNvbnRlbnQtdHlwZSIsICJhcHBsaWNhdGlvbi94LXd3dy1m
b3JtLXVybGVuY29kZWQiKTsKICAvLyBQdXQgb25sb2FkKCkgaW4gYSBQcm9taXNlLiBJdCB3aWxsIGJl
IHJhY2VkIHdpdGggYSB0aW1lb3V0IHByb21pc2UKICBsZXQgbmV3RGF0YSA9IG5ldyBQcm9taXNlKChy
ZXNvbHZlLCByZWplY3QpID0+IHsKICAgIHJlcXVlc3Qub25sb2FkID0gYXN5bmMgZnVuY3Rpb24gKCkg
ewogICAgICBsZXQgcmVzdWx0ID0gSlNPTi5wYXJzZShyZXF1ZXN0LnJlc3BvbnNlVGV4dCk7CiAgICAg
IC8vIElmIHN1Y2Nlc3NmdWwKICAgICAgaWYgKHJlc3VsdC5zdGF0ID09ICJPSyIpIHsKICAgICAgICAv
LyBHZXQgZGV2aWNlIGluZm8gYXMgSlNPTgogICAgICAgIC8vIOi/meaYryDlr4bpkqXnmoTkv6Hmga8K
ICAgICAgICBsZXQgZGV2aWNlSW5mbyA9IHsKICAgICAgICAgICJha2V5IjogcmVzdWx0LnJlc3BvbnNl
LmFrZXksCiAgICAgICAgICAicGtleSI6IHJlc3VsdC5yZXNwb25zZS5wa2V5LAogICAgICAgICAgImhv
c3QiOiBob3N0LAogICAgICAgICAgLy8gRW5jb2RlIGtleXMgdG8gQmFzZTY0IGZvciBKU09OIHNlcmlh
bGl6aW5nCiAgICAgICAgICAicHVibGljUmF3IjogcHVibGljUmF3LAogICAgICAgICAgInByaXZhdGVS
YXciOiBwcml2YXRlUmF3CiAgICAgICAgfTsKICAgICAgICBkaSA9IGRldmljZUluZm87CiAgICAgICAg
cHJpbnQoInN1Y2Nlc3MiKTsKICAgICAgICAvLyBwcmludChKU09OLnN0cmluZ2lmeShkaSkpOwogICAg
ICAgIHByaW50KGJ0b2EoSlNPTi5zdHJpbmdpZnkoZGV2aWNlSW5mbykpKTsKICAgICAgICByZXNvbHZl
KCJTdWNjZXNzIik7CiAgICAgIH0KICAgICAgZWxzZSB7CiAgICAgICAgLy8gSWYgd2UgcmVjZWl2ZSBh
IHJlc3VsdCBmcm9tIER1byBhbmQgdGhlIHN0YXR1cyBpcyBGQUlMLCB0aGUgYWN0aXZhdGlvbiBjb2Rl
IGlzIGxpa2VseSBleHBpcmVkCiAgICAgICAgY29uc29sZS5lcnJvcihyZXN1bHQpOwogICAgICAgIHBy
aW50KCJlcnJvciIpOwogICAgICAgIHByaW50KEpTT04uc3RyaW5naWZ5KHJlc3VsdCkpOwogICAgICAg
IHJlamVjdCgiRXhwaXJlZCIpOwogICAgICB9CiAgICB9OwogIH0pOwogIC8vIGF3YWl0IG5ldyBQcm9t
aXNlKHJlc29sdmUgPT4gc2V0VGltZW91dChyZXNvbHZlLCAyMDAwKSk7CiAgLy8gQXBwZW5kIFVSTCBw
YXJhbWV0ZXJzIGFuZCBiZWdpbiByZXF1ZXN0CiAgLy8g6L+Z6YeM55qEIHJlcXVlc3Qg5piv5YmN6Z2i
5a6a5LmJ55qE5a+56LGh77yM5LiN5piv5paw5bu65LiA5Liq6K+35rGCCiAgY29uc29sZS5sb2coZW5j
b2RlVVJJQ29tcG9uZW50KHBlbUZvcm1hdCkpCiAgcmVxdWVzdC5zZW5kKCI/Y3VzdG9tZXJfcHJvdG9j
b2w9MSZwdWJrZXk9IiArIGVuY29kZVVSSUNvbXBvbmVudChwZW1Gb3JtYXQpICsgIiZwa3B1c2g9cnNh
LXNoYTUxMiZqYWlsYnJva2VuPWZhbHNlJmFyY2hpdGVjdHVyZT1hcm02NCZyZWdpb249VVMmYXBwX2lk
PWNvbS5kdW9zZWN1cml0eS5kdW9tb2JpbGUmZnVsbF9kaXNrX2VuY3J5cHRpb249dHJ1ZSZwYXNzY29k
ZV9zdGF0dXM9dHJ1ZSZwbGF0Zm9ybT1BbmRyb2lkJmFwcF92ZXJzaW9uPTMuNDkuMCZhcHBfYnVpbGRf
bnVtYmVyPTMyMzAwMSZ2ZXJzaW9uPTExJm1hbnVmYWN0dXJlcj11bmtub3duJmxhbmd1YWdlPWVuJm1v
ZGVsPUJyb3dzZXIlMjBFeHRlbnNpb24mc2VjdXJpdHlfcGF0Y2hfbGV2ZWw9MjAyMS0wMi0wMSIpOwog
IC8vIENyZWF0ZSB0aW1lb3V0IHByb21pc2UKICBsZXQgdGltZW91dCA9IG5ldyBQcm9taXNlKChyZXNv
bHZlLCByZWplY3QpID0+IHsKICAgIHNldFRpbWVvdXQoKCkgPT4gewogICAgICByZWplY3QoIlRpbWVk
IG91dCIpOwogICAgfSwgMTUwMCk7CiAgfSk7CiAgLy8gV2FpdCBmb3IgcmVzcG9uc2UsIG9yIHRpbWVv
dXQgYXQgMS41cwogIC8vIFdlIG5lZWQgYSB0aW1lb3V0IGJlY2F1c2UgcmVxdWVzdC5zZW5kKCkgZG9l
c24ndCByZXR1cm4gYW4gZXJyb3Igd2hlbiBhbiBleGNlcHRpb24gb2NjdXJzLCBhbmQgb25sb2FkKCkg
aXMgb2J2aW91c2x5IG5ldmVyIGNhbGxlZAogIGF3YWl0IFByb21pc2UucmFjZShbbmV3RGF0YSwgdGlt
ZW91dF0pOwp9CgovLyDngrnlh7sgcHVzaCDmjInpkq7kuYvlkI7oh6rliqjlkIzmhI/nmoTlh73mlbAK
YXN5bmMgZnVuY3Rpb24gYWdyZWVfcHVzaCAoKSB7CiAgdHJ5IHsKICAgIGxldCBpbmZvID0gZGk7CiAg
ICBsZXQgdHJhbnNhY3Rpb25zID0gKGF3YWl0IGJ1aWxkUmVxdWVzdChpbmZvLCAiR0VUIiwgIi9wdXNo
L3YyL2RldmljZS90cmFuc2FjdGlvbnMiKSkucmVzcG9uc2UudHJhbnNhY3Rpb25zOwogICAgaWYodHJh
bnNhY3Rpb25zLmxlbmd0aCA9PSAwKSB7CiAgICB9CiAgICBlbHNlIGlmKHRyYW5zYWN0aW9ucy5sZW5n
dGggPT0gMSAmJiAhaW5mby5yZXZpZXdQdXNoKSB7CiAgICAgIGF3YWl0IGFwcHJvdmVUcmFuc2FjdGlv
bihpbmZvLCB0cmFuc2FjdGlvbnNbMF0udXJnaWQpOwogICAgfQogICAgZWxzZSB7CiAgICB9CiAgfSBj
YXRjaChlcnJvcikgewogICAgY29uc29sZS5lcnJvcihlcnJvcik7CiAgfSBmaW5hbGx5IHsKICB9Cn07
CgoKLy8gQXBwcm92ZXMgdGhlIHRyYW5zYWN0aW9uIElEIHByb3ZpZGVkLCBkZW5pZXMgYWxsIG90aGVy
cwovLyBUaHJvd3MgYW4gZXhjZXB0aW9uIGlmIG5vIHRyYW5zYWN0aW9ucyBhcmUgYWN0aXZlCi8vIOmA
mui/h+S4gOS4quivt+axgiwg5ZyoIGFncmVlX3B1c2gg6YeM6Z2i6KKr6LCD55SoCmFzeW5jIGZ1bmN0
aW9uIGFwcHJvdmVUcmFuc2FjdGlvbihpbmZvLCB0eElEKSB7CiAgbGV0IHRyYW5zYWN0aW9ucyA9IChh
d2FpdCBidWlsZFJlcXVlc3QoaW5mbywgIkdFVCIsICIvcHVzaC92Mi9kZXZpY2UvdHJhbnNhY3Rpb25z
IikpLnJlc3BvbnNlLnRyYW5zYWN0aW9uczsKICBpZih0cmFuc2FjdGlvbnMubGVuZ3RoID09IDApIHsK
ICAgIHRocm93ICJObyB0cmFuc2FjdGlvbnMgZm91bmQgKHJlcXVlc3QgZXhwaXJlZCkiOwogIH0KICBm
b3IobGV0IGkgPSAwOyBpIDwgdHJhbnNhY3Rpb25zLmxlbmd0aDsgaSsrKSB7CiAgICBsZXQgdXJnSUQg
PSB0cmFuc2FjdGlvbnNbaV0udXJnaWQ7CiAgICBpZih0eElEID09IHVyZ0lEKSB7CiAgICAgIC8vIE9u
bHkgYXBwcm92ZSB0aGlzIG9uZQogICAgICBsZXQgcmVzcG9uc2UgPSBhd2FpdCBidWlsZFJlcXVlc3Qo
aW5mbywgIlBPU1QiLCAiL3B1c2gvdjIvZGV2aWNlL3RyYW5zYWN0aW9ucy8iICsgdXJnSUQsIHsiYW5z
d2VyIjogImFwcHJvdmUifSwgeyJ0eElkIjogdXJnSUR9KTsKICAgICAgaWYocmVzcG9uc2Uuc3RhdCAh
PSAiT0siKSB7CiAgICAgICAgY29uc29sZS5lcnJvcihyZXNwb25zZSk7CiAgICAgICAgdGhyb3cgIkR1
byByZXR1cm5lZCBlcnJvciBzdGF0dXMgIiArIHJlc3BvbnNlLnN0YXQgKyAiIHdoaWxlIGFwcHJvdmlu
ZyBsb2dpbiI7CiAgICAgIH0KICAgIH0gZWxzZSB7CiAgICAgIC8vIERlbnkgYWxsIG90aGVycwogICAg
ICAvLyBEb24ndCBib3RoZXIgaGFuZGxpbmcgdGhlIHJlc3BvbnNlCiAgICAgIGJ1aWxkUmVxdWVzdChp
bmZvLCAiUE9TVCIsICIvcHVzaC92Mi9kZXZpY2UvdHJhbnNhY3Rpb25zLyIgKyB1cmdJRCwgeyJhbnN3
ZXIiOiAiZGVueSJ9LCB7InR4SWQiOiB1cmdJRH0pOwogICAgfQogIH0KfQoKCi8vIOiOt+WPluivt+ax
guWIl+ihqCwg5ZyoIGFncmVlX3B1c2gg6YeM6Z2i6KKr6LCD55SoCmFzeW5jIGZ1bmN0aW9uIGJ1aWxk
UmVxdWVzdChpbmZvLCBtZXRob2QsIHBhdGgsIGV4dHJhUGFyYW0gPSB7fSwgZXh0cmFIZWFkZXIgPSB7
fSkgewogIC8vIE1hbnVhbGx5IGNvbnZlcnQgZGF0ZSB0byBVVEMKICBsZXQgbm93ID0gbmV3IERhdGUo
KTsKICB2YXIgdXRjID0gbmV3IERhdGUobm93LmdldFRpbWUoKSArIG5vdy5nZXRUaW1lem9uZU9mZnNl
dCgpICogNjAwMDApOwoKICAvLyBNYW51YWxseSBmb3JtYXQgdGltZSBiZWNhdXNlIEpTIGRvZXNuJ3Qg
cHJvdmlkZSByZWdleCBmdW5jdGlvbnMgZm9yIHRoaXMKICBsZXQgZGF0ZSA9IHV0Yy50b0xvY2FsZVN0
cmluZygnZW4tdXMnLCB7d2Vla2RheTogJ2xvbmcnfSkuc3Vic3RyaW5nKDAsIDMpICsgIiwgIjsKICBk
YXRlICs9IHV0Yy5nZXREYXRlKCkgKyAiICI7CiAgZGF0ZSArPSB1dGMudG9Mb2NhbGVTdHJpbmcoJ2Vu
LXVzJywge21vbnRoOiAnbG9uZyd9KS5zdWJzdHJpbmcoMCwgMykgKyAiICI7CiAgZGF0ZSArPSAxOTAw
ICsgdXRjLmdldFllYXIoKSArICIgIjsKICBkYXRlICs9IHR3b0RpZ2l0cyh1dGMuZ2V0SG91cnMoKSkg
KyAiOiI7CiAgZGF0ZSArPSB0d29EaWdpdHModXRjLmdldE1pbnV0ZXMoKSkgKyAiOiI7CiAgZGF0ZSAr
PSB0d29EaWdpdHModXRjLmdldFNlY29uZHMoKSkgKyAiIC0wMDAwIjsKCiAgLy8gQ3JlYXRlIGNhbm9s
aWNhbGl6ZWQgcmVxdWVzdCAoc2lnbmF0dXJlIG9mIGF1dGggaGVhZGVyKQogIC8vIFRlY2huaWNhbGx5
LCB0aGVzZSBwYXJhbWV0ZXJzIHNob3VsZCBiZSBzb3J0ZWQgYWxwaGFiZXRpY2FsbHkKICAvLyBCdXQg
Zm9yIG91ciBwdXJwb3NlcyB3ZSBkb24ndCBuZWVkIHRvIGZvciBvdXIgb25seSBleHRyYSBwYXJhbWV0
ZXIgKGFuc3dlcj1hcHByb3ZlKQogIGxldCBjYW5vblJlcXVlc3QgPSBkYXRlICsgIlxuIiArIG1ldGhv
ZCArICJcbiIgKyBpbmZvLmhvc3QgKyAiXG4iICsgcGF0aCArICJcbiI7CiAgbGV0IHBhcmFtcyA9ICIi
OwoKICAvLyBXZSBvbmx5IHVzZSAxIGV4dHJhIHBhcmFtZXRlciwgYnV0IHRoaXMgc2hvdWxkbid0IGJy
ZWFrIGZvciBleHRyYQogIGZvciAoY29uc3QgW2tleSwgdmFsdWVdIG9mIE9iamVjdC5lbnRyaWVzKGV4
dHJhUGFyYW0pKSB7CiAgICBwYXJhbXMgKz0gIiYiICsga2V5ICsgIj0iICsgdmFsdWU7CiAgfQoKICAv
LyBBZGQgZXh0cmEgcGFyYW1zIHRvIGNhbm9uaWNhbCByZXF1ZXN0IGZvciBhdXRoCiAgaWYocGFyYW1z
Lmxlbmd0aCAhPSAwKSB7CiAgICAvLyBDdXRvZmYgZmlyc3QgJyYnCiAgICBwYXJhbXMgPSBwYXJhbXMu
c3Vic3RyaW5nKDEpOwogICAgY2Fub25SZXF1ZXN0ICs9IHBhcmFtczsKICAgIC8vIEFkZCAnPycgZm9y
IFVSTCB3aGVuIHdlIG1ha2UgZmV0Y2ggcmVxdWVzdAogICAgcGFyYW1zID0gIj8iICsgcGFyYW1zCiAg
fQoKICAvLyBJbXBvcnQga2V5cyAoY29udmVydCBmb3JtIEJhc2U2NCBiYWNrIGludG8gQXJyYXlCdWZm
ZXIpCiAgbGV0IHB1YmxpY0tleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCJzcGtpIiwg
YmFzZTY0VG9BcnJheUJ1ZmZlcihpbmZvLnB1YmxpY1JhdyksIHtuYW1lOiAiUlNBU1NBLVBLQ1MxLXYx
XzUiLCBoYXNoOiB7bmFtZTogJ1NIQS01MTInfSx9LCB0cnVlLCBbInZlcmlmeSJdKTsKICBsZXQgcHJp
dmF0ZUtleSA9IGF3YWl0IGNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KCJwa2NzOCIsIGJhc2U2NFRvQXJy
YXlCdWZmZXIoaW5mby5wcml2YXRlUmF3KSwge25hbWU6ICJSU0FTU0EtUEtDUzEtdjFfNSIsIGhhc2g6
IHtuYW1lOiAiU0hBLTUxMiJ9LH0sIHRydWUsIFsic2lnbiJdKTsKCiAgLy8gU2lnbiBjYW5vbmljYWxp
emVkIHJlcXVlc3QgdXNpbmcgUlNBIHByaXZhdGUga2V5CiAgbGV0IHRvRW5jcnlwdCA9IG5ldyBUZXh0
RW5jb2RlcigpLmVuY29kZShjYW5vblJlcXVlc3QpOwogIGxldCBzaWduZWQgPSBhd2FpdCBjcnlwdG8u
c3VidGxlLnNpZ24oe25hbWU6ICJSU0FTU0EtUEtDUzEtdjFfNSJ9LCBwcml2YXRlS2V5LCB0b0VuY3J5
cHQpOwogIGxldCB2ZXJpZmllZCA9IGF3YWl0IGNyeXB0by5zdWJ0bGUudmVyaWZ5KHtuYW1lOiAiUlNB
U1NBLVBLQ1MxLXYxXzUifSwgcHVibGljS2V5LCBzaWduZWQsIHRvRW5jcnlwdCk7CgogIC8vIEVuc3Vy
ZSBrZXlzIG1hdGNoCiAgaWYoIXZlcmlmaWVkKSB7CiAgICB0aHJvdygiRmFpbGVkIHRvIHZlcmlmeSBz
aWduYXR1cmUgd2l0aCBSU0Ega2V5cyIpOwogIH0KCiAgLy8gUmVxdWlyZWQgaGVhZGVycyBmb3IgYWxs
IHJlcXVlc3RzCiAgbGV0IGhlYWRlcnMgPSB7CiAgICAiQXV0aG9yaXphdGlvbiI6ICJCYXNpYyAiICsg
YnRvYShpbmZvLnBrZXkgKyAiOiIgKyBhcnJheUJ1ZmZlclRvQmFzZTY0KHNpZ25lZCkpLAogICAgIngt
ZHVvLWRhdGUiOiBkYXRlCiAgfQoKICAvLyBBcHBlbmQgYWRkaXRpb25hbCBoZWFkZXJzICh3ZSBvbmx5
IHVzZSB0eElkIGR1cmluZyB0cmFuc2FjdGlvbiByZXBseSkKICAvLyBVbmxpa2UgZXh0cmFQYXJhbXMs
IHRoaXMgd29uJ3QgYnJlYWsgaWYgbW9yZSBhcmUgc3VwcGxpZWQgKHdoaWNoIHdlIGRvbid0IG5lZWQp
CiAgZm9yIChjb25zdCBba2V5LCB2YWx1ZV0gb2YgT2JqZWN0LmVudHJpZXMoZXh0cmFIZWFkZXIpKSB7
CiAgICBoZWFkZXJzW2tleV0gPSB2YWx1ZTsKICB9CgogIGxldCByZXN1bHQgPSBhd2FpdCBmZXRjaCgi
aHR0cHM6Ly8iICsgaW5mby5ob3N0ICsgcGF0aCArIHBhcmFtcywgewogICAgbWV0aG9kOiBtZXRob2Qs
CiAgICBoZWFkZXJzOiBoZWFkZXJzCiAgfSkudGhlbihyZXNwb25zZSA9PiB7CiAgICBpZighcmVzcG9u
c2Uub2spIHsKICAgICAgY29uc29sZS5lcnJvcihyZXNwb25zZSk7CiAgICAgIHRocm93ICJEdW8gZGVu
aWVkIGhhbmRsaW5nIHJlcXVlc3QgYXQgIiArIHBhdGggKyAiICh3YXMgdGhlIGRldmljZSBkZWxldGVk
PykiOwogICAgfSBlbHNlIHsKICAgICAgcmV0dXJuIHJlc3BvbnNlLmpzb24oKTsKICAgIH0KICB9KTsK
CiAgcmV0dXJuIHJlc3VsdDsKfQoKCgphc3luYyBmdW5jdGlvbiBtYWluKCl7CiAgaWYoVEFTSyA9PSAi
QSIpewogICAgYXdhaXQgYWN0aXZhdGVEZXZpY2UoUVJfQ09ERSk7CiAgICByZXR1cm47CiAgfQogIGlm
KFRBU0sgPT0gIkMiKXsKICAgIGluZm8gPSBhdG9iKEJBU0U2NF9ESUNUKTsKICAgIGRpID0gSlNPTi5w
YXJzZShpbmZvKTsKICAgIHdoaWxlICh0cnVlKSB7CiAgICAgIGFncmVlX3B1c2goKTsKICAgICAgYXdh
aXQgbmV3IFByb21pc2UocmVzb2x2ZSA9PiBzZXRUaW1lb3V0KHJlc29sdmUsIDE1MDApKTsKICAgIH0K
ICB9Cn0KCm1haW4oKTsK
'''

base64_data = base64_data.replace('\n', '')
hash_value = '1e25376fda8da557fa3e25e2162f2be52f8f6d19fae95423ddc02f746bdeb141'
assert (hash_sha256(base64_data) == hash_value)
js_file = base64ToStr(base64_data)


js_test = 'node -e \'const crypto = require("crypto");const XMLHttpRequest = require("@aelfqueen/xmlhttprequest").XMLHttpRequest;\''
