from __future__ import division  # py3 "true division"
import os
import random
import itertools
from gensim import utils, matutils
import logging

logger = logging.getLogger(__name__)


class PathLineSentences:
    def __init__(self, source, max_sentence_length=500, limit=None):
        """Like :class:`~gensim.models.word2vec.LineSentence`, but process all files in a directory
        in alphabetical order by filename.
        The directory must only contain files that can be read by :class:`gensim.models.word2vec.LineSentence`:
        .bz2, .gz, and text files. Any file not ending with .bz2 or .gz is assumed to be a text file.
        The format of files (either text, or compressed text files) in the path is one sentence = one line,
        with words already preprocessed and separated by whitespace.
        Warnings
        --------
        Does **not recurse** into subdirectories.
        Parameters
        ----------
        source : str
            Path to the directory.
        limit : int or None
            Read only the first `limit` lines from each file. Read all if limit is None (the default).
        """
        self.source = source
        self.max_sentence_length = max_sentence_length
        self.limit = limit

        if os.path.isfile(self.source):
            logger.debug('single file given as source, rather than a directory of files')
            logger.debug('consider using models.word2vec.LineSentence for a single file')
            self.input_files = [self.source]  # force code compatibility with list of files
        elif os.path.isdir(self.source):
            self.source = os.path.join(self.source, '')  # ensures os-specific slash at end of path
            logger.info('reading directory %s', self.source)
            self.input_files = os.listdir(self.source)
            self.input_files = [self.source + filename for filename in self.input_files]  # make full paths
            self.input_files.sort()  # makes sure it happens in filename order
        else:  # not a file or a directory, then we can't do anything with it
            raise ValueError('input is neither a file nor a path')
        logger.info('files read into PathLineSentences:%s', '\n'.join(self.input_files))

    def __iter__(self):
        """iterate through the files"""
        for file_name in self.input_files:
            logger.info('reading file %s', file_name)
            with utils.open(file_name, 'rb') as fin:
                for line in itertools.islice(fin, self.limit):
                    line = utils.to_unicode(line).split('\t')[1].strip().split(',')
                    for i in range(25):
                        random.shuffle(line)
                        # print(line)
                    i = 0
                    while i < len(line):
                        yield line[
                              i: i + self.max_sentence_length]  # if max_sentence_length = 10:[d1....d10] / [d10...d20]
                        i += self.max_sentence_length
                        # print(line)


import numpy as np
from gensim.models import word2vec
import os
from gensim.models import word2vec
import gensim
import logging
# from mypathline import PathLineSentences
import random


def model_train(train_file_name, save_model_file):  # model_file_name为训练语料的路径,save_model为保存模型名
    # 模型训练，生成词向量
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.INFO)
    sentences = PathLineSentences(train_file_name)  # 加载语料
    model = gensim.models.Word2Vec(sentences, vector_size=100)  # 训练skip-gram模型; 默认window=5
    model.save(save_model_file)
    model.wv.save_word2vec_format(save_model_name + ".bin", binary=True)  # 以二进制类型保存模型以便重


file = 'prac0.txt'
save_model_name = 'pracx.model'
if not os.path.exists(save_model_name):  # 判断文件是否存在
    model_train(file, save_model_name)
else:
    print('此训练模型已经存在，不用再次训练')

# 加载已训练好的模型
model_1 = word2vec.Word2Vec.load(save_model_name)

# word_dic= model_1.wv.get_normed_vectors()
# print(word_dic)
# labels = DBSCAN_d(word_dic)
# print(labels)

# 计算两个词的相似度
# y1 = model_1.wv.similarity("xxmh169.com","xxmh205.com")
y1 = model_1.wv.similarity("shqqy.com", "a51y.com")
print("这两个词的相似度为:", y1)
print('\n')

# 计算某个词的相关词列表
y2 = model_1.wv.most_similar("szgfey.wang", topn=22)  # 10个最相关的
print(u"和该词最相关的词有：")
for item in y2:
    print(item[0], item[1])