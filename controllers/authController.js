const catchAsync = require('./../utils/catchAsync');
const { promisify } = require('util')
const AppError = require('./../utils/appError');
const User = require('../models/userModel');
const jwt = require('jsonwebtoken');


const createJWT = (user) => {
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET_KEY, { expiresIn: process.env.JWT_EXPIRES_IN });
    return token
}

exports.signUp = catchAsync(async (req, res, next) => {
    const user = await User.create(
        {
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            passwordConfirm: req.body.passwordConfirm,
        }
    );

    const token = createJWT(user);

    res.status(200).json({
        message: "success",
        token,
        data: user
    });

})

exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return next(AppError("Please provide email and password!", 400));
    }

    const user = await User.findOne({ email }).select('+password');

    let checkPass;
    if (user) {
        checkPass = await user.checkPassword(password, user.password);
    }

    if (!user || !checkPass) {
        return next(new AppError("Incorrect credentials!", 401));
    }

    const token = createJWT(user);

    res.status(200).json({
        message: "success",
        token,
        data: user
    });

})

exports.protect = catchAsync(async (req, res, next) => {
    // 1) Getting token and check of it's there
    let token;
    if (
        req.headers.authorization &&
        req.headers.authorization.startsWith('Bearer')
    ) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return next(
            new AppError('You are not logged in! Please log in to get access.', 401)
        );
    }

    // 2) Verification token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET_KEY);

    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
        return next(
            new AppError(
                'The user belonging to this token does no longer exist.',
                401
            )
        );
    }

    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return next(
            new AppError('User recently changed password! Please log in again.', 401)
        );
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
});

