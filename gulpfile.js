const gulp = require("gulp");
const pug = require("gulp-pug");
const sass = require("gulp-sass")(require("sass"));
const babel = require("gulp-babel");
const browserSync = require("browser-sync").create();
const autoprefixer = require("gulp-autoprefixer");
const imagemin = require('gulp-imagemin')
const plumber = require('gulp-plumber');


const gulp_files = ["pug", "scss", "js"];

const pug_files = "./src/views/**/*.pug";
const scss_files = "./src/scss/**/*.scss";
const js_files = "./src/js/**/*.js";

gulp.task("serve", async function () {
//   browserSync.init({
//     server: "./dist",
//   });

  gulp.watch(
    [pug_files, scss_files, js_files],
    gulp.series("pug", "scss", "js")
  );
//   gulp.watch("dist/**/*").on("change", browserSync.reload);
});

gulp.task("pug", async () => {
  gulp.src(pug_files).pipe(plumber()).pipe(pug({pretty: true})).pipe(gulp.dest("./templates"));
});

gulp.task("image", async () => {
  gulp.src("./src/img/**/*").pipe(imagemin()).pipe(gulp.dest("./static/img"));
});

gulp.task("scss", async () => {
  return gulp
    .src(scss_files)
    .pipe(sass().on("error", sass.logError))
    .pipe(
      autoprefixer({
        cascade: false,
      })
    )
    .pipe(gulp.dest("./static/css"));
});

gulp.task("js", async () =>
  gulp
    .src(js_files)
    .pipe(
      babel({
        // presets: ["@babel/env", {modules: false }],
        // ignore: [ "./src/js/particles.min.js" ],
        // plugins: [['@babel/transform-runtime', { regenerator: true }]]
      })
    )
    .pipe(gulp.dest("./static/js"))
);

gulp.task("default", gulp.series(gulp_files, "serve"));