output "vpc_id" {
  value = aws_vpc.lab_vpc.id
}

output "sensitive_bucket" {
  value = aws_s3_bucket.sensitive_data.bucket
}

output "test_user" {
  value = aws_iam_user.test_user.name
}