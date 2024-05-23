CREATE DATABASE IF NOT EXISTS `spam_user_db`;

CREATE USER 'admino'@'%' IDENTIFIED WITH mysql_native_password BY 'SpamMysql@1234';
GRANT ALL PRIVILEGES ON spam_user_db.* TO 'admino'@'%';
FLUSH PRIVILEGES;
