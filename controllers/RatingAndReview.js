const { default: mongoose } = require("mongoose");
const Course = require("../models/Course");
const RatingAndReview = require("../models/RatingAndReview");


//createRaiting
exports.createRating = async(req, res) => {
    try{
        //get user id
        const userId = req.user.id

        //fetch data from req body
        const {rating , review, courseId} = req.body;

        //check if user is enrolled or not
        const courseDetails = await Course.findOne({_id:courseId, studentsEnroled: {$elemMatch: {$eq: userId}},});

        if(!courseDetails){
            return res.status(400).json({
                success: false,
                message: 'Student is not enrolled in the course',
            });
        }

        //check if user already reviewed the course
        const alreadyReviewed = await RatingAndReview.findOne({
            user:userId,
            course: courseId,
        });

        if (alreadyReviewed) {
            return res.status(403).json({
            success: false,
            message: "Course is already reviewed by the use",
            });
        }

        //create ratind and review
        const ratingReview = await RatingAndReview.create({
            rating, 
            review,
            course: courseId,
            user: userId
        });

        //update course with this rating/review
        const updatedCourseDetails = await Course.findByIdAndUpdate({_id:courseId},
            {
                $push:{
                    ratingAndReviews: ratingReview._id,
                }
            }, 
            {new:true}
        );
        console.log(updatedCourseDetails);

        //return review
        return res.status(200).json({
            success: true,
            message: "Rating and Review Created Successfully",
            ratingReview
        })

    }catch(error){
        console.log(error);
        return res.status(500).json({
            success: false,
            message:error.message
        })
    }
}


//getAveragerating
exports.getAverageRating = async(req, res) => {
    try {
        //get course id
        const courseId = req.body.courseId;

        //calculate avg rating 
        const result = await RatingAndReview.aggregate([
            {
                $match:{
                    course: new mongoose.Types.ObjectId(courseId)
                }
            },
            {
                $group:{
                    _id: null,
                    averageRating: {$avg: "$rating"},
                }
            }
        ])

        //return rating 
        if(result.length > 0){
            return res.status(200).json({
                success: true,
                averageRating: result[0].averageRating,
            })
        }

        //if no rating/Review exist
        return res.status(200).json({
            success: true,
            message: "Average Rating is 0, no rating given till now",
            averageRating: 0,
        })

    } catch (error) {
      console.log(error);
      return res.status(500).json({
        success: false,
        message: error.message,
      });
    }
}


//getAllRatingAndReviews
exports.getAllRatingReview = async (req, res) => {
  try {
    const allReviews = await RatingAndReview.find({})
      .sort({ rating: "desc" })
      .populate({
        path: "user",
        select: "firstName lastName email image", // Specify the fields you want to populate from the "Profile" model
      })
      .populate({
        path: "course",
        select: "courseName",
      })
      .exec();

    return res.status(200).json({
      success: true,
      message: "All reviews fetched successfully",
      data: allReviews,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};