const { constants } = require("../constants");
const errorhandler = (err, req, res, next) => {
    const statusCode = res.statuscode ? res.statusCode : 500;
    switch (statusCode) {
        case constants.VALIDATION_ERROR:
            res.json({ title: "Validation failled", message: err.message, stackTrace: err.stack });
            break;
        case constants.NOT_FOUND:
            res.json({ title: "Not Found", message: err.message, stackTrace: err.stack });
            break;
        case constants.UNAUTHORISED:
                res.json({ title: "Unauthorised", message: err.message, stackTrace: err.stack });
                break; 
        case constants.FORBIDDEN:
            res.json({ title: "Fobidden", message: err.message, stackTrace: err.stack });
            break;  
        case constants.SERVER_ERROR:
            res.json({ title: "Server Error", message: err.message, stackTrace: err.stack });
            break;      
        default:
            console.log("No error");
            break    

    }




};
module.exports = errorhandler;