export const asyncHandler = (requestHandler) => async (req,res,next) => {
    try {
        await requestHandler(req,res,next)
    } catch (e) {
        res.status(e.code | 500).json({
            success : false,
            message: e.message
        })
    }
}

//We made this to standardize the async handler so we dont have to write it again and again.
//Try to handle errors using nodejs error class