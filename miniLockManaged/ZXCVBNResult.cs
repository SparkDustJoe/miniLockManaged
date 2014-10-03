using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MFZ = Zxcvbn;

//taken straight from Michael Ford's library of code, it is used here to "box" the results in a way that doesn't
//  require a caller to miniLockManaged to also have an "include" or "using" or DLL reference to ZXCVBN

// TODO: These should probably be immutable
namespace miniLockManaged.ZXCVBN
{
    /// <summary>
    /// The results of zxcvbn's password analysis
    /// </summary>
    public class Result
    {
        /// <summary>
        /// A calculated estimate of how many bits of entropy the password covers, rounded to three decimal places.
        /// </summary>
        public double Entropy { get; set; }

        /// <summary>
        /// The number of milliseconds that zxcvbn took to calculate results for this password
        /// </summary>
        public long CalcTime { get; set; }

        /// <summary>
        /// An estimation of the crack time for this password in seconds
        /// </summary>
        public double CrackTime { get; set; }

        /// <summary>
        /// A friendly string for the crack time (like "centuries", "instant", "7 minutes", "14 hours" etc.)
        /// </summary>
        public string CrackTimeDisplay { get; set; }

        /// <summary>
        /// A score from 0 to 4 (inclusive), with 0 being least secure and 4 being most secure calculated from crack time:
        /// [0,1,2,3,4] if crack time is less than [10**2, 10**4, 10**6, 10**8, Infinity] seconds.
        /// Useful for implementing a strength meter
        /// </summary>
        public int Score { get; set; }

        /// <summary>
        /// The sequence of matches that were used to create the entropy calculation
        /// </summary>
        public IList<miniLockManaged.ZXCVBN.Match> MatchSequence { get; set; }

        
        //REMOVED to prevent password leaking (c# strings NOT immutable)
        /// <summary>
        /// The password that was used to generate these results
        /// </summary>
        //public string Password { get; set; }

        // constructor added to ease the "boxing" methodology
        internal Result(MFZ.Result source)
        {
            this.CalcTime = source.CalcTime;
            this.CrackTime = source.CrackTime;
            this.CrackTimeDisplay = source.CrackTimeDisplay;
            this.Entropy = source.Entropy;
            if (source.MatchSequence != null)
            {
                this.MatchSequence = new List<miniLockManaged.ZXCVBN.Match>();
                foreach (MFZ.Match m in source.MatchSequence)
                {
                    this.MatchSequence.Add(new Match(m));
                }
            }
            this.Score = source.Score;
            //source.Password not used!
        }
    }

    /// <summary>
    /// <para>A single match that one of the pattern matchers has made against the password being tested.</para>
    /// 
    /// <para>Some pattern matchers implement subclasses of match that can provide more information on their specific results.</para>
    /// 
    /// <para>Matches must all have the <see cref="Pattern"/>, <see cref="Token"/>, <see cref="Entropy"/>, <see cref="i"/> and
    /// <see cref="j"/> fields (i.e. all but the <see cref="Cardinality"/> field, which is optional) set before being returned from the matcher
    /// in which they are created.</para>
    /// </summary>
    public class Match
    {
        /// <summary>
        /// The name of the pattern matcher used to generate this match
        /// </summary>
        public string Pattern { get; set; }

        /// <summary>
        /// The portion of the password that was matched
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// The entropy that this portion of the password covers using the current pattern matching technique
        /// </summary>
        public double Entropy { get; set; }


        // The following are more internal measures, but may be useful to consumers

        /// <summary>
        /// Some pattern matchers can associate the cardinality of the set of possible matches that the 
        /// entropy calculation is derived from. Not all matchers provide a value for cardinality.
        /// </summary>
        public int Cardinality { get; set; }

        /// <summary>
        /// The start index in the password string of the matched token. 
        /// </summary>
        public int i { get; set; } // Start Index

        /// <summary>
        /// The end index in the password string of the matched token.
        /// </summary>
        public int j { get; set; } // End Index

        // constructor added to ease the "boxing" methodology
        internal Match(MFZ.Match source)
        {
            this.Cardinality = source.Cardinality;
            this.Entropy = source.Entropy;
            this.i = source.i;
            this.j = source.j;
            this.Pattern = source.Pattern;
            this.Token = source.Token;
        }
    }

}
