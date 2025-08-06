// types/signature_version.h

#ifndef AWS_STS_SIGNATURE_VERSION_H
#define AWS_STS_SIGNATURE_VERSION_H

/**
 * @brief Validates the AWS SignatureVersion parameter.
 *
 * This function checks whether the input string matches a supported
 * signature version (e.g., "2" or "4").
 *
 * @param input The signature version string to validate.
 * @return 1 if valid, 0 otherwise.
 */
int signature_version_is_valid(const char *input);

#endif // AWS_STS_SIGNATURE_VERSION_H
