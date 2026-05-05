permit(
    principal == Role::"arn:aws:iam::2222:role/DevTeam",
    action == Action::"read",
    resource == Bucket::"arn:aws:s3:::app-logs-01"
);