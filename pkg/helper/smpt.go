package smtp

import (
	"authserver/config"
	"net/smtp"
)

func Sendmail(toEmail string, msg string) error {

	/// Compose the email message
	from := "luckguy7011@gmail.com"
	to := []string{toEmail}
	subject := "Register for UZUMCLONE-Market"
	message := msg

	// Create the email message
	body := "To:" + to[0] + "\r\n" + "Subject: " + subject + "\r\n" + "r\n" + message

	auth := smtp.PlainAuth("", config.SmtpUsername, config.SmtpPassword, config.SmtpServer)

	//Connection to the SMTP servfer

	err := smtp.SendMail(config.SmtpServer+":"+config.SmtpPort, auth, from, to, []byte(body))

	if err != nil {
		return err
	}

	return nil

}
