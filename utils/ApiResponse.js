class ApiResponse {
    constructor(statusCode, data, message) {
        this.statusCode = statusCode;
        this.data = data;
        this.message = message;
    }

    toJSON() {
        return {
            statusCode: this.statusCode,
            data: this.data,
            message: this.message
        };
    }
}
export default ApiResponse;