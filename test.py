from vat import platform as v3

client = v3.ClientV3_latest(
    url="https://203120373595.uw2.portal.vectra.ai",
    client_id="22a6e038ef6b441f9b6f773fdba454b0",
    secret_key="WFFGTk1CRkNSNFhFNEZQVkY1QjJFU0RCVVlHWUJVSEY1TDVWUFdLTEhFRU1STEk2RlJIQUU_Z2wkazJeOFA4Qj8yb0c",
)

for audit in client.get_audits():
    print(audit)
