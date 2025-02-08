class ApiError extends Error{
    constructor(statuscode,message,error){
        super(message)
        this.statuscode=statuscode;
        this.message=message;
        this.error=error;

        Error.captureStackTrace(this,this.constructor)
    }
}

export default ApiError;