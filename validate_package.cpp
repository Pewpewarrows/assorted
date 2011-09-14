#include <windows.h>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>

/*
 *	Usage:
 *
 *		if (! validate_package(
 *		        L"C:\\Temp\\bvckup-update.exe",
 *		        L"Bvckup Setup", 
 *		        L"Yaletown Software Design Inc."))
 *		{
 *			...
 *
 */
bool validate_package(const wchar_t * file_name,
                      const wchar_t * application_name
                      const wchar_t * cert_subject_name)
{
	bool    ok = false;
	int     i;
	
	DWORD encoding, content_type, format_type, bytes;
	HCERTSTORE store = NULL;
	HCRYPTMSG  msg = NULL;
	CMSG_SIGNER_INFO * signer = NULL;
	SPC_SP_OPUS_INFO * opus = NULL;
	CERT_INFO cert_info;
	PCCERT_CONTEXT cert = NULL;
	WCHAR subject[128];

	WINTRUST_FILE_INFO file_info = { sizeof(file_info) };
	WINTRUST_DATA     trust_data = { sizeof(trust_data) };
	GUID  policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	BOOL  res;
	DWORD ret;

	/*
	 *	Validate details of application signature
	 *	http://support.microsoft.com/kb/323809
	 */
        res = CryptQueryObject(
			CERT_QUERY_OBJECT_FILE,
			file_name,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&encoding,        //  NULL
			&content_type,
			&format_type,
			&store,
			&msg,
			NULL);

        if (! res)
	{
//		log->printf("updater: CryptQueryObject() failed, %d\n", GetLastError());
		return false;
	}

	// Get signer information size.
	res = CryptMsgGetParam(
			msg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL, 
			&bytes);
	
	if (! res || ! bytes)
	{
//		log->printf("updater: CryptMsgGetParam(0) failed, %d\n", GetLastError());
		goto exit;
	}

	signer = (CMSG_SIGNER_INFO *)new char [bytes];
//	assert_goto(signer, exit);

	res = CryptMsgGetParam(
			msg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			signer, 
			&bytes);
	if (! res)
	{
//		log->printf("updater: CryptMsgGetParam() failed, %d\n", GetLastError());
		goto exit;
	}

	/*
	 *	Check program name
	 */
	for (i = 0; i < signer->AuthAttrs.cAttr; i++)
	{
		CRYPT_ATTRIBUTE * attr = signer->AuthAttrs.rgAttr + i;

		if (lstrcmpA(SPC_SP_OPUS_INFO_OBJID, attr->pszObjId))
			continue;

		res = CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				attr->rgValue[0].pbData,
				attr->rgValue[0].cbData,
				0,
				NULL,
				&bytes);

		if (! res || ! bytes)
		{
//			log->printf("updater: CryptDecodeObject(0) failed, %d\n", GetLastError());
			goto exit;
		}

		opus = (SPC_SP_OPUS_INFO *)new char [bytes];
//		assert_goto(opus, exit);

		// Decode and get SPC_SP_OPUS_INFO structure.
		res = CryptDecodeObject(
				X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				SPC_SP_OPUS_INFO_OBJID,
				attr->rgValue[0].pbData,
				attr->rgValue[0].cbData,
				0,
				opus,
				&bytes);
		if (! res)
		{
//			log->printf("updater: CryptDecodeObject() failed, %d\n", GetLastError());
			goto exit;
		}

		// Check program name
		if (! opus->pwszProgramName ||
		      wcscmp(opus->pwszProgramName, application_name) )
		{
//			log->printf("updater: invalid ProgramName, [%s]\n", to_utf8(opus->pwszProgramName).c_str() );
			goto exit;
		}

		break;
	}

	if (! opus)
	{
//		log->printf("updater: ProgramName not found\n");
		goto exit;
	}

	/*
	 *	Check certificate Subject
	 */
	cert_info.Issuer = signer->Issuer;
	cert_info.SerialNumber = signer->SerialNumber;

	cert = CertFindCertificateInStore(
			store,
			X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			&cert_info,
			NULL);

	if (! cert)
	{
//		log->printf("updater: CertFindCertificateInStore() failed, %d\n", GetLastError());
		goto exit;
	}

	res = CertGetNameString(
			cert,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			subject,
			sizeof(subject) / 2);
	if (! res)
	{
//		log->printf("updater: CertGetNameString() failed, %d\n", GetLastError());
		goto exit;
	}

	if (wcscmp(subject, cert_subject_name))
	{
//		log->printf("updater: invalid SubjectName, [%s]\n", to_utf8(subject).c_str());
		goto exit;
	}

	/*
	 *	Validate certificate trust
	 *	http://msdn.microsoft.com/en-us/library/aa382384(VS.85).aspx
	 */
	file_info.pcwszFilePath = file_name;

	trust_data.dwUIChoice = WTD_UI_NONE;
	trust_data.fdwRevocationChecks = WTD_REVOKE_NONE; 
	trust_data.dwUnionChoice = WTD_CHOICE_FILE;
	trust_data.dwProvFlags = WTD_SAFER_FLAG;
	trust_data.pFile = &file_info;

	ret = WinVerifyTrust(NULL, &policy_guid, &trust_data);
	if (ret != ERROR_SUCCESS)
	{
//		log->printf("updater: WinVerifyTrust() failed, %d\n", GetLastError());
		goto exit;
	}

//	log->printf("updater: package is valid\n");

	ok = true;

exit:
	if (cert) CertFreeCertificateContext(cert);

	delete [] opus;
	delete [] signer;

	if (store) CertCloseStore(store, 0);
	
	if (msg) CryptMsgClose(msg);

	return ok;
}
