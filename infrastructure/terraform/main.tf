resource "aws_vpc" "lab_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = { Name = "aegiscloud-lab-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.lab_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "aegiscloud-public-subnet" }
}

resource "aws_s3_bucket" "sensitive_data" {
  bucket = "aegiscloud-sensitive-data"
  tags = { Name = "aegiscloud-sensitive-bucket" }
}

resource "aws_iam_user" "test_user" {
  name = "test-analyst"
  tags = { Purpose = "aegiscloud-attack-scenario-1" }
}

resource "aws_iam_policy" "read_only" {
  name = "aegiscloud-read-only"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "attach_read_only" {
  user       = aws_iam_user.test_user.name
  policy_arn = aws_iam_policy.read_only.arn
}