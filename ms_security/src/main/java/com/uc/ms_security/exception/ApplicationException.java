package com.uc.ms_security.exception;

public class ApplicationException extends RuntimeException {

    private final ErrorCase errorCase;

    public ApplicationException(ErrorCase errorCase, String message) {
        super(message);
        this.errorCase = errorCase;
    }

    public ApplicationException(ErrorCase errorCase, String message, Throwable cause) {
        super(message, cause);
        this.errorCase = errorCase;
    }

    public ErrorCase getErrorCase() {
        return errorCase;
    }
}