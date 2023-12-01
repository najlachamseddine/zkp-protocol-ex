docker tag protocolserver:latest <aws_account_id>.dkr.ecr.<region>.amazonaws.com/zkpprotocolserver:latest
docker push <aws_account_id>.dkr.ecr.<region>.amazonaws.com/zkpprotocolserver:latest

docker tag protocolclient:latest <aws_account_id>.dkr.ecr.<region>.amazonaws.com/zkpprotocolclient:latest
docker push <aws_account_id>.dkr.ecr.<region>.amazonaws.com/zkpprotocolclient:latest