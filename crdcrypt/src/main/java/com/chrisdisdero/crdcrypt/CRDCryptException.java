package com.chrisdisdero.crdcrypt;

/**
 * Class that provides a single exception type for {@link CRDCrypt}.
 *
 * @author cdisdero.
 *
Copyright © 2017 Christopher Disdero.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */
public class CRDCryptException extends Exception {

    //region Private members

    /**
     * Log tag for this class.
     */
    private static final String TAG = CRDCryptException.class.getCanonicalName();

    /**
     * The class name from where the exception is thrown
     */
    private String className = null;

    /**
     * The method name from where the exception is thrown
     */
    private String methodName = null;

    /**
     * The underlying or original exception if any
     */
    private Exception underlyingException = null;

    //endregion

    //region Constructors

    /**
     * Constructs a new {@link CRDCryptException} exception object using the given message.
     *
     * @param className           the class name
     * @param methodName          the method name
     * @param message             The specific message to assign to this exception.
     * @param underlyingException the underlying exception
     *
     * @return A new {@link CRDCryptException} exception object.
     *
     * @author cdisdero
     */
    public CRDCryptException(String className, String methodName, String message, Exception underlyingException) {

        // Call the super class to instantiate the exception, passing the given message to use.
        super(message);

        this.className = className;
        this.methodName = methodName;
        this.underlyingException = underlyingException;
    }

    /**
     * Constructs a new {@link CRDCryptException} exception object using the given message.
     *
     * @param className           the class name
     * @param methodName          the method name
     * @param message             The specific message to assign to this exception.
     */
    public CRDCryptException(String className, String methodName, String message) {

        // Call the super class to instantiate the exception, passing the given message to use.
        super(message);

        this.className = className;
        this.methodName = methodName;
    }

    //endregion

    //region Public properties

    /**
     * Gets the class name where this exception occurred.
     *
     * @return the class name
     */
    public String getClassName() {

        return className;
    }

    /**
     * Gets method name where this exception occurred.
     *
     * @return the method name
     */
    public String getMethodName() {

        return methodName;
    }

    /**
     * Gets underlying exception.
     *
     * @return the underlying exception
     */
    public Exception getUnderlyingException() {

        return underlyingException;
    }

    //endregion
}
